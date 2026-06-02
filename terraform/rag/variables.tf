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

variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
}

variable "tfc_base_workspace" {
  type        = string
  description = "TFC base workspace name"
  default     = "base"
}

variable "inbound_cidrs_for_lbs" {
  description = "CIDR blocks allowed to access Langflow ingress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "langflow_secret_key" {
  description = "Langflow secret key"
  type        = string
  sensitive   = true
}

variable "langflow_auto_login" {
  description = "Enable auto-login for Langflow. Override when needed"
  type        = bool
  default     = false
}

variable "tfe_token" {
  description = "HCP Terraform API token for terraform-mcp-server"
  type        = string
  sensitive   = true
}

variable "mcp_admin_email" {
  description = "Admin email for MCP Context Forge platform administrator"
  type        = string
  default     = "admin@example.com"
}