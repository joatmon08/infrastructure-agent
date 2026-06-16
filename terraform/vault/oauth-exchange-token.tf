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
  "issuer": "${var.vault_private_endpoint}/v1/${var.oauth_token_exchange_secrets_path}",
  "actor_token_jwks_uri": "${var.vault_private_endpoint}/v1/identity/oidc/.well-known/keys",
  "actor_token_jwks_skip_verify": true
}
EOT

  depends_on = [vault_generic_endpoint.sts_key]
}

resource "vault_policy" "oauth_exchange_token" {
  for_each = var.client_agents
  name     = "${each.key}-oauth-exchange-token"

  policy = <<EOT
path "${var.oauth_token_exchange_secrets_path}/token/${each.key}" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "vault_token_creator" {
  for_each = var.client_agents
  name     = "${each.key}-vault-token-creator"

  policy = <<EOT
# Allow tokens to be created under the token auth method
path "auth/token/create" {
  capabilities = ["create", "update"]
}

# Allow creating child tokens by specifying explicit roles
path "auth/token/create/${each.key}" {
  capabilities = ["create", "update"]
}

# Allow checking token capabilities and lookups
path "auth/token/lookup" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow token renewals
path "auth/token/renew" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

resource "vault_token_auth_backend_role" "client_agents" {
  for_each                = var.client_agents
  role_name               = each.key
  allowed_policies        = ["${each.key}-oauth-exchange-token"]
  disallowed_policies     = ["default"]
  orphan                  = true
  token_period            = "86400"
  renewable               = true
  token_explicit_max_ttl  = "115200"
  token_no_default_policy = true
}