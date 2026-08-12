output "summarizer_agent_url" {
  description = "URL to access summarizer-agent"
  value       = length(data.kubernetes_ingress_v1.summarizer_agent.status) > 0 && length(data.kubernetes_ingress_v1.summarizer_agent.status[0].load_balancer) > 0 && length(data.kubernetes_ingress_v1.summarizer_agent.status[0].load_balancer[0].ingress) > 0 ? "http://${data.kubernetes_ingress_v1.summarizer_agent.status[0].load_balancer[0].ingress[0].hostname}" : "pending"
}

output "ollama_endpoint" {
  description = "In-cluster endpoint for Ollama inference server"
  value       = "http://ollama.ollama.svc.cluster.local:11434"
}
