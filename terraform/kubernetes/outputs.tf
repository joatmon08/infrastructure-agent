# Logins for Vault userpass
output "helloworld_agent_client_login" {
  description = "The login command for the helloworld-agent-client"
  value       = "vault login -method=userpass username=${local.client_username} password=${random_password.helloworld_agent_client.result}"
  sensitive   = true
}

output "helloworld_agent_server_login" {
  description = "The login command for the helloworld-agent-server"
  value       = "vault login -method=userpass username=${local.server_username} password=${random_password.helloworld_agent_server.result}"
  sensitive   = true
}

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
  value       = "http://${kubernetes_service_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}"
}

output "helloworld_agent_server_url" {
  description = "URL to access helloworld-agent-server"
  value       = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}"
}