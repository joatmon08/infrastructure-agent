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