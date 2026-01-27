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

output "opensearch_collection" {
  description = "OpenSearch Serverless collection"
  value       = module.opensearch_serverless.opensearch_serverless_collection
}

output "opensearch_vector_index" {
  description = "Vector index of OpenSearch Serverless collection"
  value       = module.opensearch_serverless.vector_index
}

# IRSA Outputs
output "opensearch_irsa_role_arn" {
  description = "ARN of the IAM role for OpenSearch IRSA"
  value       = aws_iam_role.opensearch_irsa.arn
}

output "opensearch_service_account_name" {
  description = "Name of the Kubernetes service account for OpenSearch"
  value       = var.opensearch_service_account
}

output "opensearch_namespace" {
  description = "Kubernetes namespace for OpenSearch service account"
  value       = var.opensearch_namespace
}