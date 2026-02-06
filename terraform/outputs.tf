# VPC Outputs
output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs"
  value       = module.vpc.natgw_ids
}

# EKS Cluster Outputs
output "cluster_id" {
  description = "The ID of the EKS cluster"
  value       = module.eks.cluster_id
}

output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN of the EKS cluster"
  value       = module.eks.cluster_iam_role_arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = module.eks.cluster_oidc_issuer_url
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC Provider for EKS"
  value       = module.eks.oidc_provider_arn
}

# Node Group Outputs
output "eks_managed_node_groups" {
  description = "Map of attribute maps for all EKS managed node groups created"
  value       = module.eks.eks_managed_node_groups
}

output "eks_managed_node_groups_autoscaling_group_names" {
  description = "List of the autoscaling group names created by EKS managed node groups"
  value       = module.eks.eks_managed_node_groups_autoscaling_group_names
}

# ECR Repository Outputs
output "ecr_repository_arns" {
  description = "List of ARNs for all ECR repositories"
  value = [
    aws_ecr_repository.ollama.arn,
    aws_ecr_repository.langflow.arn
  ]
}

output "ecr_repository_urls" {
  description = "List of URLs for all ECR repositories"
  value = [
    aws_ecr_repository.ollama.repository_url,
    aws_ecr_repository.langflow.repository_url
  ]
}

# IAM Policy Output
output "ecr_pull_policy_arn" {
  description = "ARN of the IAM policy for ECR pull access"
  value       = aws_iam_policy.ecr_pull_policy.arn
}

# Configuration Output
output "configure_kubectl" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

# HCP Vault Cluster Outputs
output "vault_cluster_id" {
  description = "The ID of the HCP Vault cluster"
  value       = hcp_vault_cluster.main.cluster_id
}

output "vault_public_endpoint_url" {
  description = "The public endpoint URL of the HCP Vault cluster"
  value       = hcp_vault_cluster.main.vault_public_endpoint_url
}

output "vault_private_endpoint_url" {
  description = "The private endpoint URL of the HCP Vault cluster"
  value       = hcp_vault_cluster.main.vault_private_endpoint_url
}

output "vault_namespace" {
  description = "The namespace of the HCP Vault cluster"
  value       = hcp_vault_cluster.main.namespace
}

output "vault_admin_token" {
  description = "The admin token for the HCP Vault cluster"
  value       = hcp_vault_cluster_admin_token.main.token
  sensitive   = true
}

output "helloworld_agent_client_login" {
  description = "The login command for the helloworld-agent-client"
  value       = "vault login -method=userpass username=${local.client_username} password=${random_password.helloworld_agent_client.result}"
  sensitive   = true
}

output "helloworld_agent_server_login" {
  description = "The login command for the helloworld-agent-server"
  value       = "vault login -method=userpass username=${local.server_username} password=${random_password.helloworld_agent_server.result}"
  sensitive   = true
}