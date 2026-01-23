# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# VPC Module
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.6.0"

  name = "${var.project_name}-${var.environment}-vpc"
  cidr = var.vpc_cidr

  azs             = slice(data.aws_availability_zones.available.names, 0, length(var.private_subnet_cidrs))
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway   = var.enable_nat_gateway
  single_nat_gateway   = var.single_nat_gateway
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Tags for EKS
  public_subnet_tags = {
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.project_name}" = "shared"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.project_name}" = "shared"
  }
}

# EKS Module with Auto Mode
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name                     = var.project_name
  iam_role_use_name_prefix = false
  kubernetes_version       = var.cluster_version

  # Cluster endpoint access
  endpoint_public_access = true

  # Cluster addons
  enable_cluster_creator_admin_permissions = true

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  # Enable EKS Auto Mode
  # Auto Mode automatically manages compute capacity
  compute_config = {
    enabled    = true
    node_pools = ["general-purpose", "system"]
  }
}

# ECR Repositories
resource "aws_ecr_repository" "ollama" {
  name                 = "${var.project_name}-ollama"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "${var.project_name}-ollama"
  }
}

resource "aws_ecr_repository" "langflow" {
  name                 = "${var.project_name}-langflow"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "${var.project_name}-langflow"
  }
}

resource "aws_ecr_repository" "opensearch" {
  name                 = "${var.project_name}-opensearch"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "${var.project_name}-opensearch"
  }
}

# IAM Policy for ECR Access
resource "aws_iam_policy" "ecr_pull_policy" {
  name        = "${var.project_name}-ecr-pull-policy"
  description = "Policy to allow EKS nodes to pull images from ECR repositories"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ecr-pull-policy"
  }
}

# Attach ECR pull policy to EKS node role
# Note: EKS Auto Mode creates node roles automatically
# We need to attach the policy to the node role created by Auto Mode
resource "aws_iam_role_policy_attachment" "eks_node_ecr_policy" {
  policy_arn = aws_iam_policy.ecr_pull_policy.arn
  role       = module.eks.cluster_iam_role_name
}

# Additional attachment for worker nodes if using managed node groups
# This ensures nodes can pull from ECR regardless of the compute configuration
data "aws_iam_policy" "ecr_read_only" {
  arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "eks_node_ecr_readonly" {
  policy_arn = data.aws_iam_policy.ecr_read_only.arn
  role       = module.eks.cluster_iam_role_name
}

# OpenSearch Serverless Collection
resource "aws_opensearchserverless_security_policy" "encryption" {
  name = "${var.project_name}-encryption-policy"
  type = "encryption"
  policy = jsonencode({
    Rules = [
      {
        Resource = [
          "collection/langflow"
        ]
        ResourceType = "collection"
      }
    ]
    AWSOwnedKey = true
  })
}

resource "aws_opensearchserverless_security_policy" "network" {
  name = "${var.project_name}-network-policy"
  type = "network"
  policy = jsonencode([
    {
      Rules = [
        {
          Resource = [
            "collection/langflow"
          ]
          ResourceType = "collection"
        }
      ]
      AllowFromPublic = false
      SourceVPCEs = [
        aws_opensearchserverless_vpc_endpoint.this.id
      ]
    }
  ])
}

resource "aws_opensearchserverless_vpc_endpoint" "this" {
  name               = "${var.project_name}-vpce"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [aws_security_group.opensearch_serverless.id]
}

resource "aws_security_group" "opensearch_serverless" {
  name        = "${var.project_name}-opensearch-serverless-sg"
  description = "Security group for OpenSearch Serverless VPC endpoint"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-opensearch-serverless-sg"
  }
}

# IAM role for OpenSearch Serverless access from EKS
resource "aws_iam_role" "opensearch_access" {
  name = "${var.project_name}-opensearch-access-role"

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
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:default:opensearch-access"
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-opensearch-access-role"
  }
}

resource "aws_iam_policy" "opensearch_access" {
  name        = "${var.project_name}-opensearch-access-policy"
  description = "Policy for EKS pods to access OpenSearch Serverless"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "aoss:APIAccessAll"
        ]
        Resource = aws_opensearchserverless_collection.langflow.arn
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-opensearch-access-policy"
  }
}

resource "aws_iam_role_policy_attachment" "opensearch_access" {
  policy_arn = aws_iam_policy.opensearch_access.arn
  role       = aws_iam_role.opensearch_access.name
}

resource "aws_opensearchserverless_access_policy" "data_access" {
  name = "${var.project_name}-data-access-policy"
  type = "data"
  policy = jsonencode([
    {
      Rules = [
        {
          Resource = [
            "collection/langflow"
          ]
          Permission = [
            "aoss:CreateCollectionItems",
            "aoss:DeleteCollectionItems",
            "aoss:UpdateCollectionItems",
            "aoss:DescribeCollectionItems"
          ]
          ResourceType = "collection"
        },
        {
          Resource = [
            "index/langflow/*"
          ]
          Permission = [
            "aoss:CreateIndex",
            "aoss:DeleteIndex",
            "aoss:UpdateIndex",
            "aoss:DescribeIndex",
            "aoss:ReadDocument",
            "aoss:WriteDocument"
          ]
          ResourceType = "index"
        }
      ]
      Principal = [
        aws_iam_role.opensearch_access.arn
      ]
    }
  ])
}

resource "aws_opensearchserverless_collection" "langflow" {
  name = "langflow"
  type = "VECTORSEARCH"

  depends_on = [
    aws_opensearchserverless_security_policy.encryption,
    aws_opensearchserverless_security_policy.network
  ]

  tags = {
    Name = "langflow"
  }
}

resource "opensearch_index" "langflow" {
  name                           = "langflow"
  index_knn                      = true
  index_knn_algo_param_ef_search = "512"
  mappings                       = <<-EOF
    {
      "properties": {
        "chunk_embedding": {
          "type": "knn_vector",
          "dimension": 384
        }
      }
    }
  EOF
}