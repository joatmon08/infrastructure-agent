locals {
  client_username = "test-client"
  server_username = "helloworld-server"
  vault_endpoint  = length(kubernetes_ingress_v1.vault_ui.status) > 0 && length(kubernetes_ingress_v1.vault_ui.status[0].load_balancer) > 0 && length(kubernetes_ingress_v1.vault_ui.status[0].load_balancer[0].ingress) > 0 ? "https://${kubernetes_ingress_v1.vault_ui.status[0].load_balancer[0].ingress[0].hostname}" : "https://vault-pending"
}