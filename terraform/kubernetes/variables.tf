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

variable "vault_helm_chart_version" {
  description = "Version of the HashiCorp Vault Helm chart to use"
  type        = string
  default     = "0.32.0"
}

variable "kubernetes_namespace_vault" {
  type        = string
  description = "Kubernetes namespace for Vault"
  default     = "vault"
}

variable "allow_hcp_terraform_to_access_vault" {
  type        = bool
  description = "Allow HCP Terraform to configure Vault, sets CIDR range to 0.0.0.0/0 for Vault load balancer"
  default     = true
}

variable "server_tls_servername" {
  type        = string
  description = "Vault server TLS servername"
  default     = "vault.joatmon08.com"
}


variable "vault_plugins" {
  description = "List of Vault plugins to download and install"
  type = list(object({
    name   = string
    url    = string
    sha256 = string
  }))
  default = []
}