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

resource "aws_ecr_repository" "helloworld_agent" {
  name                 = "${var.project_name}-helloworld-agent"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "${var.project_name}-helloworld-agent"
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