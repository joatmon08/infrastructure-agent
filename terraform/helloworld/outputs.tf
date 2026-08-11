output "helloworld_agent_server_url" {
  description = "URL to access helloworld-server"
  value       = length(data.kubernetes_ingress_v1.helloworld_server.status) > 0 && length(data.kubernetes_ingress_v1.helloworld_server.status[0].load_balancer) > 0 && length(data.kubernetes_ingress_v1.helloworld_server.status[0].load_balancer[0].ingress) > 0 ? "http://${data.kubernetes_ingress_v1.helloworld_server.status[0].load_balancer[0].ingress[0].hostname}" : "pending"
}

output "test_client_url" {
  description = "URL to access test-client"
  value       = length(data.kubernetes_ingress_v1.test_client.status) > 0 && length(data.kubernetes_ingress_v1.test_client.status[0].load_balancer) > 0 && length(data.kubernetes_ingress_v1.test_client.status[0].load_balancer[0].ingress) > 0 ? "http://${data.kubernetes_ingress_v1.test_client.status[0].load_balancer[0].ingress[0].hostname}" : "pending"
}
