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
