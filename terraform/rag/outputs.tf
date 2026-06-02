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

output "opensearch_service_name" {
  description = "Name of the OpenSearch Kubernetes service"
  value       = kubernetes_service_v1.opensearch.metadata[0].name
}

output "opensearch_endpoint" {
  description = "Internal endpoint to access OpenSearch service"
  value       = "https://${kubernetes_service_v1.opensearch.metadata[0].name}:9200"
}

output "opensearch_admin_password" {
  description = "OpenSearch admin password (sensitive)"
  value       = random_password.opensearch_admin.result
  sensitive   = true
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

output "mcp_context_forge_url" {
  description = "URL to access MCP Context Forge"
  value       = "pending - check ingress status after deployment"
}

output "mcp_context_forge_admin_email" {
  description = "MCP Context Forge admin email"
  value       = var.mcp_admin_email
}

output "mcp_context_forge_admin_password" {
  description = "MCP Context Forge admin password (sensitive)"
  value       = random_password.mcp_admin_password.result
  sensitive   = true
}