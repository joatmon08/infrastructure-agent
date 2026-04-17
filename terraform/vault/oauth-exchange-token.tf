resource "vault_generic_endpoint" "sts_enable" {
  path                 = "sys/mounts/${var.oauth_token_exchange_secrets_path}"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "type": "vault-plugin-secrets-oauth-token-exchange"
}
EOT
}

data "vault_identity_oidc_openid_config" "provider" {
  name = vault_identity_oidc_provider.agent.name
}

resource "vault_generic_endpoint" "sts_config" {
  path                 = "${var.oauth_token_exchange_secrets_path}/config"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "client_id": "${vault_identity_oidc_client.agent.client_id}",
  "client_secret": "${vault_identity_oidc_client.agent.client_secret}",
  "subject_token_jwks_uri": "${data.vault_identity_oidc_openid_config.provider.jwks_uri}",
  "subject_token_jwks_skip_verify": true
}
EOT

  depends_on = [vault_generic_endpoint.sts_enable]
}

resource "vault_generic_endpoint" "sts_key" {
  path                 = "${var.oauth_token_exchange_secrets_path}/key/${local.sts_key_name}"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "allowed_client_ids": "*"
}
EOT

  depends_on = [vault_generic_endpoint.sts_config]
}

resource "vault_generic_endpoint" "sts_role" {
  for_each             = var.client_agents
  path                 = "${var.oauth_token_exchange_secrets_path}/role/${each.key}"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "key": "${local.sts_key_name}",
  "issuer": "${data.vault_identity_oidc_openid_config.provider.issuer}",
  "actor_token_jwks_uri": "https://vault-ui.vault/v1/identity/oidc/.well-known/keys",
  "actor_token_jwks_skip_verify": true
}
EOT

  depends_on = [vault_generic_endpoint.sts_key]
}

resource "vault_policy" "oauth_exchange_token" {
  for_each = var.client_agents
  name     = "agent-oauth-exchange-token"

  policy = <<EOT
path "${var.oauth_token_exchange_secrets_path}/token/${each.key}" {
  capabilities = [ "read" ]
}
EOT
}