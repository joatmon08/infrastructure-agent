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