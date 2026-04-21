output "end_user_password_path" {
  description = "Path to the end user password in Vault KV store"
  value       = "${vault_mount.credentials.path}/data/${vault_kv_secret_v2.end_user_password.name}"
}

output "openid_connect_url" {
  description = "OpenID Connect URL for the helloworld agent"
  value       = "${local.vault_endpoint}/v1/identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/.well-known/openid-configuration"
}

output "vault_kubernetes_auth_backend_path" {
  description = "Path of the Kubernetes auth backend"
  value       = vault_auth_backend.kubernetes.path
}

output "vault_userpass_auth_backend_path" {
  description = "Path of the userpass auth backend"
  value       = vault_auth_backend.userpass.path
}

output "client_agent_vault_tokens" {
  value       = { for agent, attributes in vault_approle_auth_backend_login.client_agents : agent => attributes.client_token }
  description = "Vault tokens generated for AppRole client agents"
  sensitive   = true
}

output "helloworld_agent_server_url" {
  description = "URL to access helloworld-agent-server (passed through from kubernetes workspace)"
  value       = data.terraform_remote_state.kubernetes.outputs.helloworld_agent_server_url
}

output "test_client_url" {
  description = "URL to access test-client (passed through from kubernetes workspace)"
  value       = data.terraform_remote_state.kubernetes.outputs.test_client_url
}

output "vault_private_endpoint" {
  description = "Private endpoint for Vault"
  value       = var.vault_private_endpoint
}