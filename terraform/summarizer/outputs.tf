output "summarizer_agent_url" {
  description = "URL to access summarizer-agent"
  value       = data.terraform_remote_state.kubernetes.outputs.summarizer_agent_url
}

output "ollama_endpoint" {
  description = "In-cluster endpoint for Ollama inference server"
  value       = "http://ollama.ollama.svc.cluster.local:11434"
}
