# ECR Repositories
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

resource "aws_ecr_repository" "test_client" {
  name                 = "${var.project_name}-test-client"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = {
    Name = "${var.project_name}-test-client"
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

# Attach the custom ECR pull policy to the GPU node group role.
# The default managed node group receives ECR access via
# iam_role_additional_policies inside the eks module block.
resource "aws_iam_role_policy_attachment" "gpu_node_group_ecr_pull_policy" {
  policy_arn = aws_iam_policy.ecr_pull_policy.arn
  role       = aws_iam_role.gpu_node_group.name
}