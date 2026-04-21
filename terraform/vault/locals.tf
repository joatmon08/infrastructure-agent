locals {
  client_username = "test-client"
  end_user        = "end-user"
  vault_endpoint  = data.terraform_remote_state.kubernetes.outputs.vault_endpoint

  sts_key_name = "agent"

  may_act_scope_name = "may-act"
  may_act_claim      = jsonencode([for agent, info in var.client_agents : { client_id = agent, sub = vault_identity_entity.client_agents[agent].id }])
}