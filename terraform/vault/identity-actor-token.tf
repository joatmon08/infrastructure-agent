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