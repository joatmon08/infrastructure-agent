data "http" "vault_cors" {
  url      = "${data.terraform_remote_state.base.outputs.vault_endpoint}/v1/sys/config/cors"
  insecure = true
  method   = "POST"

  request_headers = {
    X-Vault-Token = var.vault_token
  }

  request_body = jsonencode({
    enabled = true,
    allowed_headers = [
      "Access-Control-Allow-Origin"
    ],
    allowed_origins = [
      "http://localhost:9000",
      data.terraform_remote_state.base.outputs.vault_endpoint
    ]
  })
}

data "kubernetes_service_account_v1" "vault_auth" {
  metadata {
    name      = data.terraform_remote_state.base.outputs.helm_vault_name
    namespace = data.terraform_remote_state.base.outputs.helm_vault_namespace
  }
}

resource "kubernetes_secret_v1" "vault_auth" {
  metadata {
    name      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
    namespace = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    annotations = {
      "kubernetes.io/service-account.name"      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
      "kubernetes.io/service-account.namespace" = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = data.terraform_remote_state.base.outputs.cluster_endpoint
  kubernetes_ca_cert     = kubernetes_secret_v1.vault_auth.data["ca.crt"]
  token_reviewer_jwt     = kubernetes_secret_v1.vault_auth.data.token
  disable_iss_validation = "true"
}

resource "vault_kubernetes_auth_backend_role" "test_client" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = local.client_username
  bound_service_account_names      = [local.client_username]
  bound_service_account_namespaces = ["default"]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.agent_oidc_client.name]
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

resource "random_password" "end_user" {
  length  = 16
  special = false
}

locals {
  client_username = "test-client"
  server_username = "helloworld-agent-server"
  end_user        = "end-user"
}

resource "vault_generic_endpoint" "end_user" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${local.end_user}"
  ignore_absent_fields = true
  data_json            = <<EOT
{
  "token_policies": ["${vault_policy.agent_oidc.name}"],
  "token_ttl": "1h",
  "password": "${random_password.end_user.result}"
}
EOT
}

resource "vault_identity_entity" "end_user" {
  name = local.end_user
}

resource "vault_identity_group" "agent" {
  name = "agent"
  type = "internal"
  member_entity_ids = [
    vault_identity_entity.end_user.id
  ]
}

resource "vault_identity_oidc_assignment" "end_user" {
  name = "${local.end_user}-assignment"
  entity_ids = [
    vault_identity_entity.end_user.id,
  ]
  group_ids = [
    vault_identity_group.agent.id,
  ]
}

resource "vault_identity_oidc" "server" {
  issuer = data.terraform_remote_state.base.outputs.vault_endpoint
}

resource "vault_identity_oidc_key" "agent" {
  name               = "agent"
  algorithm          = "RS256"
  allowed_client_ids = ["*"]
  verification_ttl   = 7200
  rotation_period    = 3600
}

locals {
  test_client_dev_redirect_uris = [
    "http://${kubernetes_service_v1.test_client.metadata.0.name}/callback",
    "http://localhost:9000/callback"
  ]
  test_client_redirect_uris = kubernetes_service_v1.test_client.status != null ? concat(local.test_client_dev_redirect_uris, ["http://${kubernetes_service_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}/callback"]) : local.test_client_dev_redirect_uris
}

resource "vault_identity_oidc_client" "agent" {
  name          = "agent"
  redirect_uris = local.test_client_redirect_uris
  assignments = [
    vault_identity_oidc_assignment.end_user.name,
  ]
  key              = vault_identity_oidc_key.agent.name
  id_token_ttl     = 3600
  access_token_ttl = 7200
}

resource "vault_identity_oidc_scope" "helloworld_read" {
  name        = "helloworld-read"
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
  issuer_host   = replace(data.terraform_remote_state.base.outputs.vault_endpoint, "https://", "")
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

resource "vault_identity_entity_alias" "end_user" {
  name           = local.end_user
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.end_user.id
}

data "vault_identity_oidc_openid_config" "agent" {
  name = vault_identity_oidc_provider.agent.name
}
