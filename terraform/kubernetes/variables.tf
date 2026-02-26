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

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "infrastructure-agent"
}

variable "inbound_cidrs_for_lbs" {
  type        = list(string)
  description = "Comma-separated list of inbound CIDRs"
  default     = ["0.0.0.0/0"]
}

variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
}

variable "tfc_base_workspace" {
  type        = string
  description = "TFC base workspace name"
  default     = "base"
}

variable "vault_token" {
  type        = string
  description = "Vault token"
  sensitive   = true
}