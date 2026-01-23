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
        },
        {
          "Resource" = [
            "collection/langflow"
          ],
          "ResourceType" = "dashboard"
        },
      ]
      AllowFromPublic = true
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