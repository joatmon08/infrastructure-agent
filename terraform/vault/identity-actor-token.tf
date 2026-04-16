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

resource "vault_identity_entity_alias" "client_agents" {
  for_each       = var.client_agents
  name           = each.key
  mount_accessor = vault_auth_backend.kubernetes.accessor
  canonical_id   = vault_identity_entity.client_agents[each.key].id
}

resource "vault_identity_oidc_role" "client_agents" {
  for_each  = var.client_agents
  name      = each.key
  key       = "default"
  client_id = each.key
  template  = jsonencode(merge(each.value.claims, { client_id = each.key }))
}

resource "vault_kubernetes_auth_backend_role" "client_agents" {
  for_each                         = var.client_agents
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = each.key
  bound_service_account_names      = [each.key]
  bound_service_account_namespaces = [each.value.k8s_namespace]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.actor_token[each.key].name]
}