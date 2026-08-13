variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "infrastructure-agent"
}

variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
}

variable "tfc_base_workspace" {
  type        = string
  description = "TFC base workspace name"
  default     = "txc-base"
}

variable "tfc_vault_workspace" {
  type        = string
  description = "TFC Vault workspace name"
  default     = "txc-vault"
}

variable "tfc_kubernetes_workspace" {
  type        = string
  description = "TFC Kubernetes workspace name"
  default     = "txc-kubernetes"
}

variable "summarizer_agent_image" {
  type        = string
  description = "Container image for the summarizer agent"
  default     = "ghcr.io/joatmon08/summarizer:sha-9e70f00"
}

variable "inbound_cidrs_for_lbs" {
  description = "CIDR blocks allowed to access load balancers"
  type        = list(string)
  default     = []
}

variable "memory_request" {
  description = "Memory request for the summarizer container"
  type        = string
  default     = "128Mi"
}

variable "memory_limit" {
  description = "Memory limit for the summarizer container"
  type        = string
  default     = "512Mi"
}

variable "cpu_request" {
  description = "CPU request for the summarizer container"
  type        = string
  default     = "100m"
}

variable "cpu_limit" {
  description = "CPU limit for the summarizer container"
  type        = string
  default     = "500m"
}

variable "verify_openid_config_tls" {
  description = "Verify TLS for OpenID Configuration endpoint"
  type        = string
  default     = "false"
}

variable "ollama_model" {
  description = "Ollama model to use for summarization"
  type        = string
  default     = "llama3.2:3b"
}

variable "summarizer_agent_auth_enabled" {
  description = "Authentication enabled for summarizer agent"
  type        = bool
  default     = false
}
