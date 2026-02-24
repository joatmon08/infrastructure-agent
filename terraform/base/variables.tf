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

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets"
  type        = bool
  default     = true
}

variable "cluster_version" {
  description = "Kubernetes version for EKS cluster (Auto Mode requires 1.33+)"
  type        = string
  default     = "1.33"
}

variable "opensearch_namespace" {
  description = "Kubernetes namespace for OpenSearch service account"
  type        = string
  default     = "default"
}

variable "opensearch_service_account" {
  description = "Kubernetes service account name for OpenSearch access"
  type        = string
  default     = "langflow-service"
}

# HCP Variables
variable "hvn_cidr" {
  description = "CIDR block for HCP HVN"
  type        = string
  default     = "172.25.16.0/20"
}

variable "vault_tier" {
  description = "Tier of the HCP Vault cluster (dev, starter_small, standard_small, standard_medium, standard_large, plus_small, plus_medium, plus_large)"
  type        = string
  default     = "PLUS_SMALL"
}

variable "vault_public_endpoint" {
  description = "Enable public endpoint for Vault cluster"
  type        = bool
  default     = true
}

variable "vault_helm_chart_version" {
  description = "Version of the HashiCorp Vault Helm chart to use"
  type        = string
  default     = "0.32.0"
}

variable "server_tls_servername" {
  type        = string
  description = "Vault server TLS servername"
  default     = "vault.joatmon08.com"
}

variable "kubernetes_namespace_vault" {
  type        = string
  description = "Kubernetes namespace for Vault"
  default     = "vault"
}

variable "inbound_cidrs_for_lbs" {
  type        = list(string)
  description = "Comma-separated list of inbound CIDRs"
  default     = ["0.0.0.0/0"]
}