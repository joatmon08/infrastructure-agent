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

resource "vault_policy" "kv_vault_token_read" {
  for_each = var.client_agents
  name     = "${each.key}-kv-vault-token-read"

  policy = <<EOT
path "${vault_mount.credentials.path}/data/${each.key}-vault-token" {
  capabilities = ["read"]
}
EOT
}

# Log into Vault via the Kubernetes auth backend using the service account JWT.
# The http data source captures the full response body, including auth.client_token,
# which vault_generic_endpoint does not expose (it only surfaces the data field).
data "http" "client_agents_k8s_login" {
  for_each = var.client_agents
  url      = "${local.vault_endpoint}/v1/auth/${vault_auth_backend.kubernetes.path}/login"
  insecure = true
  method   = "POST"

  request_headers = {
    Content-Type  = "application/json"
    X-Vault-Token = var.vault_token
  }

  request_body = jsonencode({
    role = vault_kubernetes_auth_backend_role.client_agents[each.key].role_name
    jwt  = kubernetes_secret_v1.client_agents_tokens[each.key].data.token
  })

  depends_on = [vault_kubernetes_auth_backend_role.client_agents]
}

# Store the client_token from the Kubernetes login in KV so VSO can sync it
# as a VaultStaticSecret. The token is already bound to the test-client entity.
resource "vault_kv_secret_v2" "client_agents_vault_token" {
  for_each = var.client_agents
  mount    = vault_mount.credentials.path
  name     = "${each.key}-vault-token"
  data_json_wo = jsonencode({
    token = jsondecode(data.http.client_agents_k8s_login[each.key].response_body).auth.client_token
  })
}
