output "mcp_context_forge_url" {
  description = "URL to access MCP Context Forge"
  value       = length(kubernetes_ingress_v1.mcp_context_forge.status) > 0 && length(kubernetes_ingress_v1.mcp_context_forge.status[0].load_balancer) > 0 && length(kubernetes_ingress_v1.mcp_context_forge.status[0].load_balancer[0].ingress) > 0 ? "http://${kubernetes_ingress_v1.mcp_context_forge.status[0].load_balancer[0].ingress[0].hostname}" : "pending"
}
