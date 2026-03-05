output "end_user_username" {
  description = "The username for the end user"
  value       = local.end_user
}

output "end_user_password" {
  description = "The password for the end user"
  value       = random_password.end_user.result
  sensitive   = true
}

output "test_client_url" {
  description = "URL to access test-client"
  value       = kubernetes_service_v1.test_client.status != null ? "http://${kubernetes_service_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}" : ""
}

output "helloworld_agent_server_url" {
  description = "URL to access helloworld-agent-server"
  value       = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}"
}

output "openid_connect_url" {
  description = "OpenID Connect URL for the helloworld agent"
  value       = "${data.terraform_remote_state.base.outputs.vault_endpoint}/v1/identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/.well-known/openid-configuration"
}