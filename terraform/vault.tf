resource "helm_release" "vault" {
  name             = "vault"
  namespace        = "vault"
  create_namespace = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = var.vault_helm_chart_version

  set = [{
    name  = "injector.externalVaultAddr"
    value = hcp_vault_cluster.main.vault_private_endpoint_url
  }]
}


data "kubernetes_service_account_v1" "vault_auth" {
  metadata {
    name      = "vault"
    namespace = "vault"
  }
}

resource "kubernetes_secret_v1" "vault_auth" {
  depends_on = [helm_release.vault]
  metadata {
    name      = "vault"
    namespace = "vault"
    annotations = {
      "kubernetes.io/service-account.name"      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
      "kubernetes.io/service-account.namespace" = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_auth_backend" "kubernetes" {
  depends_on = [helm_release.vault]
  type       = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  depends_on             = [helm_release.vault]
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = module.eks.cluster_endpoint
  kubernetes_ca_cert     = kubernetes_secret_v1.vault_auth.data["ca.crt"]
  token_reviewer_jwt     = kubernetes_secret_v1.vault_auth.data.token
  disable_iss_validation = "true"
}

resource "vault_policy" "agent_oidc" {
  name = "helloworld-agent-oidc"

  policy = <<EOT
path "identity/oidc/provider/agent/authorize" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "agent_oidc_client" {
  name = "helloworld-agent-oidc-client"

  policy = <<EOT
path "identity/oidc/client/agent" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "agent_identity_token" {
  name = "helloworld-agent-client-token"

  policy = <<EOT
path "identity/oidc/token/helloworld-reader" {
  capabilities = ["read"]
}
EOT
}


resource "vault_policy" "agent_identity_introspect" {
  name = "helloworld-agent-server-token-inspect"

  policy = <<EOT
path "identity/oidc/introspect" {
  capabilities = ["update"]
}

path "identity/oidc/introspect/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
}

resource "random_password" "helloworld_agent_client" {
  length  = 16
  special = false
}

resource "random_password" "helloworld_agent_server" {
  length  = 16
  special = false
}

locals {
  client_username = "helloworld-agent-client"
  server_username = "helloworld-agent-server"
}

resource "vault_generic_endpoint" "helloworld_agent_server" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${local.server_username}"
  ignore_absent_fields = true
  data_json            = <<EOT
{
  "token_policies": ["${vault_policy.agent_identity_introspect.name}"],
  "token_ttl": "1h",
  "password": "${random_password.helloworld_agent_server.result}"
}
EOT
}

resource "vault_generic_endpoint" "helloworld_agent_client" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${local.client_username}"
  ignore_absent_fields = true
  data_json            = <<EOT
{
  "token_policies": ["${vault_policy.agent_oidc.name}", "${vault_policy.agent_oidc_client.name}", "${vault_policy.agent_identity_token.name}"],
  "token_ttl": "1h",
  "password": "${random_password.helloworld_agent_client.result}"
}
EOT
}

resource "vault_identity_entity" "helloworld_agent_client" {
  name     = local.client_username
  policies = [vault_policy.agent_oidc.name, vault_policy.agent_oidc_client.name, vault_policy.agent_identity_token.name]
}

resource "vault_identity_group" "agent" {
  name = "agent"
  type = "internal"
  member_entity_ids = [
    vault_identity_entity.helloworld_agent_client.id
  ]
}

resource "vault_identity_oidc_assignment" "helloworld_agent_client" {
  name = "${local.client_username}-assignment"
  entity_ids = [
    vault_identity_entity.helloworld_agent_client.id,
  ]
  group_ids = [
    vault_identity_group.agent.id,
  ]
}

resource "vault_identity_oidc" "server" {
  issuer = hcp_vault_cluster.main.vault_public_endpoint_url
}

resource "vault_identity_oidc_key" "agent" {
  name               = "agent"
  algorithm          = "RS256"
  allowed_client_ids = ["*"]
  verification_ttl   = 7200
  rotation_period    = 3600
}

resource "vault_identity_oidc_client" "agent" {
  name = "agent"
  redirect_uris = [
    "http://127.0.0.1:9998/callback",
    "http://localhost:9998/callback",
  ]
  assignments = [
    vault_identity_oidc_assignment.helloworld_agent_client.name,
  ]
  key              = vault_identity_oidc_key.agent.name
  id_token_ttl     = 2400
  access_token_ttl = 7200
}

resource "vault_identity_oidc_scope" "helloworld_read" {
  name        = "helloworld"
  template    = <<EOT
{
  "hello_world": "read"
}
EOT
  description = "helloworld read scope"
}

resource "vault_identity_oidc_scope" "user" {
  name        = "user"
  template    = <<EOT
{
    "username": {{identity.entity.name}}
}
EOT
  description = "The user scope provides claims using Vault identity entity metadata"
}


resource "vault_identity_oidc_scope" "groups" {
  name        = "groups"
  template    = <<EOT
{
  "groups": {{identity.entity.groups.names}}
}
EOT
  description = "The groups scope provides the groups claims using Vault group membership"
}

resource "vault_identity_oidc_provider" "agent" {
  name          = "agent"
  https_enabled = true
  issuer_host   = replace(hcp_vault_cluster.main.vault_public_endpoint_url, "https://", "")
  allowed_client_ids = [
    vault_identity_oidc_client.agent.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.helloworld_read.name,
    vault_identity_oidc_scope.groups.name,
    vault_identity_oidc_scope.user.name
  ]
}

## Use for identity tokens
resource "vault_identity_oidc_role" "helloworld_reader" {
  name     = "helloworld-reader"
  key      = "default"
  template = <<EOT
{
  "scope": "hello_world:read"
}
EOT
}

resource "vault_identity_entity_alias" "helloworld_agent_client" {
  name           = local.client_username
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.helloworld_agent_client.id
}

data "vault_identity_oidc_openid_config" "agent" {
  name = vault_identity_oidc_provider.agent.name
}
