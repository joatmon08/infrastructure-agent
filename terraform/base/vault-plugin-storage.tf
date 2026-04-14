# Vault Plugin Storage Configuration
# This creates a shared storage solution for Vault custom plugins using EFS
# EFS is required because all 3 Vault replicas need simultaneous read access to plugin binaries

# EFS File System for plugin storage
resource "aws_efs_file_system" "vault_plugins" {
  creation_token = "${var.project_name}-vault-plugins"
  encrypted      = true
  kms_key_id     = aws_kms_key.vault.arn

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(
    local.common_tags,
    {
      Name    = "${var.project_name}-vault-plugins"
      Purpose = "vault-plugin-storage"
    }
  )
}

# EFS Mount Targets (one per private subnet for high availability)
resource "aws_efs_mount_target" "vault_plugins" {
  for_each = toset(module.vpc.private_subnets)

  file_system_id  = aws_efs_file_system.vault_plugins.id
  subnet_id       = each.value
  security_groups = [aws_security_group.vault_plugins_efs.id]
}

# Security Group for EFS
resource "aws_security_group" "vault_plugins_efs" {
  name_prefix = "${var.project_name}-vault-plugins-efs-"
  description = "Security group for Vault plugins EFS mount targets"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "NFS from VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${var.project_name}-vault-plugins-efs"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# EFS CSI Driver StorageClass for dynamic provisioning
resource "kubernetes_storage_class_v1" "efs" {
  metadata {
    name = "efs-sc"
  }

  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  volume_binding_mode = "Immediate"

  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId     = aws_efs_file_system.vault_plugins.id
    directoryPerms   = "755"
    gidRangeStart    = "1000"
    gidRangeEnd      = "2000"
    basePath         = "/plugins"
  }

  depends_on = [
    aws_efs_file_system.vault_plugins,
    aws_efs_mount_target.vault_plugins
  ]
}

# PersistentVolumeClaim for plugin storage
resource "kubernetes_persistent_volume_claim_v1" "vault_plugins" {
  metadata {
    name      = "vault-plugins-pvc"
    namespace = var.kubernetes_namespace_vault
    labels = {
      app  = "vault"
      type = "plugins"
    }
  }

  spec {
    access_modes       = ["ReadWriteMany"]
    storage_class_name = kubernetes_storage_class_v1.efs.metadata[0].name

    resources {
      requests = {
        storage = "5Gi"
      }
    }
  }

  depends_on = [
    kubernetes_storage_class_v1.efs,
    helm_release.vault
  ]
}

# IAM Policy for EFS CSI Driver
resource "aws_iam_policy" "efs_csi_driver" {
  name_prefix = "${var.project_name}-efs-csi-driver-"
  description = "IAM policy for EFS CSI driver"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:DescribeAccessPoints",
          "elasticfilesystem:DescribeFileSystems",
          "elasticfilesystem:DescribeMountTargets",
          "elasticfilesystem:CreateAccessPoint",
          "elasticfilesystem:DeleteAccessPoint"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

# Attach EFS policy to Vault IAM role
resource "aws_iam_role_policy_attachment" "vault_efs" {
  role       = aws_iam_role.vault.name
  policy_arn = aws_iam_policy.efs_csi_driver.arn
}

# Outputs for reference
output "vault_plugins_efs_id" {
  description = "EFS file system ID for Vault plugins"
  value       = aws_efs_file_system.vault_plugins.id
}

output "vault_plugins_pvc_name" {
  description = "PVC name for Vault plugins"
  value       = kubernetes_persistent_volume_claim_v1.vault_plugins.metadata[0].name
}