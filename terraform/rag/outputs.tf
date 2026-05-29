output "ollama_service_name" {
  description = "Name of the Ollama Kubernetes service"
  value       = kubernetes_service_v1.ollama.metadata[0].name
}

output "ollama_service_port" {
  description = "Port of the Ollama service"
  value       = kubernetes_service_v1.ollama.spec[0].port[0].port
}

output "ollama_endpoint" {
  description = "Internal endpoint to access Ollama service"
  value       = "http://${kubernetes_service_v1.ollama.metadata[0].name}:${kubernetes_service_v1.ollama.spec[0].port[0].port}"
}

output "langflow_url" {
  description = "URL to access Langflow"
  value       = length(kubernetes_ingress_v1.langflow.status) > 0 && length(kubernetes_ingress_v1.langflow.status[0].load_balancer) > 0 && length(kubernetes_ingress_v1.langflow.status[0].load_balancer[0].ingress) > 0 ? "http://${kubernetes_ingress_v1.langflow.status[0].load_balancer[0].ingress[0].hostname}" : "pending"
}

output "langflow_superuser_password" {
  description = "Langflow superuser password (sensitive)"
  value       = random_password.langflow_superuser.result
  sensitive   = true
}