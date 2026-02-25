# KMS Key for Vault Auto-Unseal
resource "aws_kms_key" "vault" {
  description             = "KMS key for Vault auto-unseal"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-${var.environment}-vault-unseal"
    Environment = var.environment
    Project     = var.project_name
    Purpose     = "vault-autounseal"
  }
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${var.project_name}-${var.environment}-vault-unseal"
  target_key_id = aws_kms_key.vault.key_id
}

# IAM Policy for Vault to use KMS
resource "aws_iam_policy" "vault_kms" {
  name        = "${var.project_name}-${var.environment}-vault-kms-unseal"
  description = "Policy for Vault to use KMS for auto-unseal"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultKMSUnseal"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.vault.arn
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-vault-kms-policy"
    Environment = var.environment
    Project     = var.project_name
  }
}

# IAM Role for Vault Service Account (IRSA)
resource "aws_iam_role" "vault" {
  name = "${var.project_name}-${var.environment}-vault-sa"

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
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:${var.kubernetes_namespace_vault}:vault"
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-${var.environment}-vault-sa-role"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Attach KMS policy to Vault IAM role
resource "aws_iam_role_policy_attachment" "vault_kms" {
  role       = aws_iam_role.vault.name
  policy_arn = aws_iam_policy.vault_kms.arn
}