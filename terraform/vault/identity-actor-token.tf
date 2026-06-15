resource "vault_policy" "actor_token" {
  for_each = var.client_agents
  name     = each.key

  policy = <<EOT
path "identity/oidc/token/${each.key}" {
  capabilities = ["read"]
}

path "${var.oauth_token_exchange_secrets_path}/token/${each.key}" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "vault_token_create" {
  for_each = var.client_agents
  name     = "${each.key}-vault-token-create"

  policy = <<EOT
# Allow creating tokens via token role for test-client
path "auth/token/create/${each.key}-sts" {
  capabilities = ["create", "update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

# Token role for test-client with oauth-exchange-token policy
# This allows VSO to create tokens with the correct policy for STS token exchange
resource "vault_token_auth_backend_role" "sts" {
  for_each               = var.client_agents
  role_name              = "${each.key}-sts"
  allowed_policies       = ["${each.key}-oauth-exchange-token"]
  orphan                 = true
  token_period           = 86400 # 24 hours in seconds
  renewable              = true
  token_explicit_max_ttl = 0
}

resource "vault_identity_entity" "client_agents" {
  for_each = var.client_agents
  name     = each.key
}

resource "vault_identity_oidc_role" "client_agents" {
  for_each  = var.client_agents
  name      = each.key
  key       = "default"
  client_id = each.key
  template  = jsonencode(merge(each.value.claims, { client_id = each.key }))
}