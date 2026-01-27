# Data source for current AWS account
data "aws_caller_identity" "current" {}

# IAM Role for Service Account (IRSA) for OpenSearch access
resource "aws_iam_role" "opensearch_irsa" {
  name = "${var.project_name}-${var.environment}-opensearch-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:${var.opensearch_namespace}:${var.opensearch_service_account}"
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-opensearch-irsa"
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Policy for OpenSearch Serverless access
resource "aws_iam_policy" "opensearch_access" {
  name        = "${var.project_name}-${var.environment}-opensearch-access"
  description = "Policy for accessing OpenSearch Serverless from Kubernetes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "aoss:APIAccessAll"
        ]
        Resource = module.opensearch_serverless.opensearch_serverless_collection.arn
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-opensearch-access"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Attach policy to IRSA role
resource "aws_iam_role_policy_attachment" "opensearch_irsa_policy" {
  role       = aws_iam_role.opensearch_irsa.name
  policy_arn = aws_iam_policy.opensearch_access.arn
}

# OpenSearch Serverless Data Access Policy
resource "aws_opensearchserverless_access_policy" "opensearch_data_access" {
  name        = "${var.project_name}-${var.environment}-data-access"
  type        = "data"
  description = "Data access policy for Kubernetes services"

  policy = jsonencode([
    {
      Rules = [
        {
          ResourceType = "collection"
          Resource = [
            "collection/${module.opensearch_serverless.opensearch_serverless_collection.name}"
          ]
          Permission = [
            "aoss:DescribeCollectionItems"
          ]
        },
        {
          ResourceType = "index"
          Resource = [
            "index/${module.opensearch_serverless.opensearch_serverless_collection.name}/*"
          ]
          Permission = [
            "aoss:DescribeIndex",
            "aoss:ReadDocument"
          ]
        }
      ]
      Principal = [
        aws_iam_role.opensearch_irsa.arn
      ]
    }
  ])
}