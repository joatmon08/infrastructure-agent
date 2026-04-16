resource "vault_identity_oidc_scope" "may_act" {
  name        = "may-act"
  template    = <<EOT
{
  "client_id": "${vault_identity_oidc_client.agent.client_id}",
  "may_act": ${local.may_act_claim}
}
EOT
  description = "May act claim that includes what agents can act on behalf of user"
}

resource "vault_policy" "agent_oidc_authorize" {
  name = "agent-oidc-authorize"

  policy = <<EOT
path "identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/authorize" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "agent_oidc_client" {
  name = "agent-oidc-client"

  policy = <<EOT
path "identity/oidc/client/${vault_identity_oidc_provider.agent.name}" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_identity_oidc_assignment" "end_user" {
  name = "${local.end_user}-assignment"
  entity_ids = [
    vault_identity_entity.end_user.id,
  ]
}

resource "vault_identity_oidc" "server" {
  issuer = local.vault_endpoint
}

resource "vault_identity_oidc_key" "agent" {
  name               = "agent"
  algorithm          = "RS256"
  allowed_client_ids = ["*"]
  verification_ttl   = 7200
  rotation_period    = 3600
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

resource "vault_identity_oidc_provider" "agent" {
  name          = "agent"
  https_enabled = true
  issuer_host   = replace(local.vault_endpoint, "https://", "")
  allowed_client_ids = [
    vault_identity_oidc_client.agent.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.may_act.name,
  ]
}