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

output "end_user_login" {
  description = "The login command for the helloworld-agent-server"
  value       = "vault login -method=userpass username=${local.end_user} password=${random_password.end_user.result}"
  sensitive   = true
}