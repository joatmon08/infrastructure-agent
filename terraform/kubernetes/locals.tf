locals {
  client_username = "test-client"
  server_username = "helloworld-agent-server"
  end_user        = "end-user"
  vault_endpoint  = "https://${data.kubernetes_service_v1.vault.status.0.load_balancer.0.ingress.0.hostname}"

  test_client_dev_redirect_uris = [
    "http://${kubernetes_service_v1.test_client.metadata.0.name}/callback",
    "http://localhost:9000/callback"
  ]

  test_client_redirect_uris = kubernetes_service_v1.test_client.status != null ? concat(
    local.test_client_dev_redirect_uris,
    ["http://${kubernetes_service_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}/callback"]
  ) : local.test_client_dev_redirect_uris
}