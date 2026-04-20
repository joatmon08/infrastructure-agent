resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "client_agents" {
  for_each       = var.client_agents
  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  role_id        = each.key
  token_policies = [vault_policy.actor_token[each.key].name, vault_policy.agent_oidc_client.name, vault_policy.oauth_exchange_token[each.key].name]
}

ephemeral "vault_approle_auth_backend_role_secret_id" "client_agents" {
  for_each  = var.client_agents
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.client_agents[each.key].role_name

  depends_on = [vault_approle_auth_backend_role.client_agents]
}

resource "vault_approle_auth_backend_login" "client_agents" {
  for_each             = var.client_agents
  backend              = vault_auth_backend.approle.path
  role_id              = vault_approle_auth_backend_role.client_agents[each.key].role_id
  secret_id_wo         = ephemeral.vault_approle_auth_backend_role_secret_id.client_agents[each.key].secret_id
  secret_id_wo_version = 1

  depends_on = [vault_approle_auth_backend_role.client_agents]
}

# resource "vault_identity_entity_alias" "client_agents_approle" {
#   for_each       = var.client_agents
#   name           = each.key
#   mount_accessor = vault_auth_backend.approle.accessor
#   canonical_id   = vault_identity_entity.client_agents[each.key].id
# }