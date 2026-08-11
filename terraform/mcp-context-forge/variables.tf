variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "inbound_cidrs_for_lbs" {
  description = "CIDR blocks allowed to access the MCP Context Forge ingress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "mcp_admin_email" {
  description = "Admin email for MCP Context Forge platform administrator"
  type        = string
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "infrastructure-agent"
}

variable "tfc_base_workspace" {
  description = "TFC base workspace name"
  type        = string
  default     = "txc-base"
}

variable "tfc_organization" {
  description = "TFC organization name"
  type        = string
}

variable "kubernetes_namespace" {
  description = "Namespace to deploy MCP Context Forge"
  type        = string
  default     = "ai-system"
}

variable "tfc_kubernetes_workspace" {
  description = "TFC kubernetes workspace name"
  type        = string
  default     = "txc-kubernetes"
}

variable "vault_token" {
  description = "Vault root token"
  type        = string
  sensitive   = true
}

variable "postgres_image" {
  description = "Container image for PostgreSQL"
  type        = string
  default     = "postgres:17"
}

variable "redis_image" {
  description = "Container image for Redis"
  type        = string
  default     = "redis:7-alpine"
}

variable "mcp_context_forge_image" {
  description = "Container image for MCP Context Forge"
  type        = string
  default     = "ghcr.io/ibm/mcp-context-forge:v1.0.7"
}
