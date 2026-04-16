locals {
  client_username = "test-client"
  server_username = "helloworld-agent-server"
  vault_endpoint  = "https://${data.kubernetes_service_v1.vault.status.0.load_balancer.0.ingress.0.hostname}"
}