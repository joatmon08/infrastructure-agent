locals {
  client_username = "test-client"
  end_user        = "end-user"
  vault_endpoint  = data.terraform_remote_state.kubernetes.outputs.vault_endpoint

  test_client_redirect_uris = data.terraform_remote_state.kubernetes.outputs.test_client_url != "" ? [
    "http://localhost:9000/callback",
    "${data.terraform_remote_state.kubernetes.outputs.test_client_url}/callback"
  ] : ["http://localhost:9000/callback"]

  sts_key_name = "agent"

  may_act_scope_name = "may-act-on-behalf-of-end-user"
  may_act_claim      = jsonencode([for agent, info in var.client_agents : { client_id = agent, sub = vault_identity_entity_alias.client_agents[agent].canonical_id }])
}