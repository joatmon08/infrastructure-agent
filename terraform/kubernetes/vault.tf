resource "helm_release" "vault" {
  name             = "vault"
  namespace        = var.kubernetes_namespace_vault
  create_namespace = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = var.vault_helm_chart_version

  values = [templatefile("${path.module}/templates/vault.yaml.tpl", {
    LOAD_BALANCER_SOURCE_RANGES = var.allow_hcp_terraform_to_access_vault ? ["0.0.0.0/0"] : concat(var.inbound_cidrs_for_lbs, [data.terraform_remote_state.base.outputs.vpc_cidr_block]),
    AWS_REGION                  = var.aws_region
    KMS_KEY_ID                  = data.terraform_remote_state.base.outputs.vault_kms_key_id
    VAULT_IAM_ROLE_ARN          = data.terraform_remote_state.base.outputs.vault_iam_role_arn
  })]

  depends_on = [
    kubernetes_storage_class_v1.auto_mode
  ]
}

data "kubernetes_service_v1" "vault" {
  metadata {
    name      = "${helm_release.vault.name}-ui"
    namespace = helm_release.vault.namespace
  }
}

resource "aws_efs_file_system" "vault_plugins" {
  creation_token = "${var.project_name}-vault-plugins"
  encrypted      = true
  kms_key_id     = data.terraform_remote_state.base.outputs.vault_kms_key_arn

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name        = "${var.project_name}-vault-plugins"
    Purpose     = "vault-plugin-storage"
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Terraform"
  }
}

resource "aws_security_group" "vault_plugins_efs" {
  name_prefix = "${var.project_name}-vault-plugins-efs-"
  description = "Security group for Vault plugins EFS mount targets"
  vpc_id      = data.terraform_remote_state.base.outputs.vpc_id

  ingress {
    description = "NFS from VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [data.terraform_remote_state.base.outputs.vpc_cidr_block]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-vault-plugins-efs"
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_efs_mount_target" "vault_plugins" {
  for_each = toset(data.terraform_remote_state.base.outputs.private_subnets)

  file_system_id  = aws_efs_file_system.vault_plugins.id
  subnet_id       = each.value
  security_groups = [aws_security_group.vault_plugins_efs.id]
}

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

  tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy_attachment" "vault_efs" {
  role       = data.terraform_remote_state.base.outputs.vault_iam_role_name
  policy_arn = aws_iam_policy.efs_csi_driver.arn
}

resource "kubernetes_config_map_v1" "vault_plugin_loader_script" {
  metadata {
    name      = "vault-plugin-loader-script"
    namespace = var.kubernetes_namespace_vault
    labels = {
      app       = "vault"
      component = "plugin-loader"
    }
  }

  data = {
    "load-plugins.sh" = templatefile("${path.module}/templates/vault-plugin-loader.sh.tpl", {
      PLUGINS = var.vault_plugins
    })
  }

  depends_on = [
    helm_release.vault
  ]
}

resource "kubernetes_job_v1" "vault_plugin_loader" {
  count = length(var.vault_plugins) > 0 ? 1 : 0

  metadata {
    name      = "vault-plugin-loader-${formatdate("YYYYMMDDhhmmss", timestamp())}"
    namespace = var.kubernetes_namespace_vault
    labels = {
      app       = "vault"
      component = "plugin-loader"
    }
  }

  spec {
    ttl_seconds_after_finished = 300

    template {
      metadata {
        labels = {
          app       = "vault"
          component = "plugin-loader"
        }
      }

      spec {
        restart_policy       = "OnFailure"
        service_account_name = "vault"

        container {
          name  = "plugin-loader"
          image = "hashicorp/vault:${var.vault_helm_chart_version}"

          command = ["/bin/sh", "/scripts/load-plugins.sh"]

          volume_mount {
            name       = "plugins"
            mount_path = "/vault/plugins"
          }

          volume_mount {
            name       = "scripts"
            mount_path = "/scripts"
            read_only  = true
          }

          resources {
            requests = {
              memory = "128Mi"
              cpu    = "100m"
            }
            limits = {
              memory = "256Mi"
              cpu    = "200m"
            }
          }

          security_context {
            run_as_non_root = true
            run_as_user     = 100
            run_as_group    = 1000
            capabilities {
              drop = ["ALL"]
            }
            read_only_root_filesystem = false
          }
        }

        volume {
          name = "plugins"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.vault_plugins.metadata[0].name
          }
        }

        volume {
          name = "scripts"
          config_map {
            name         = kubernetes_config_map_v1.vault_plugin_loader_script.metadata[0].name
            default_mode = "0755"
          }
        }

        security_context {
          fs_group = 1000
        }
      }
    }
  }

  wait_for_completion = true

  timeouts {
    create = "5m"
    update = "5m"
  }

  depends_on = [
    kubernetes_config_map_v1.vault_plugin_loader_script,
    kubernetes_persistent_volume_claim_v1.vault_plugins
  ]

  lifecycle {
    replace_triggered_by = [
      kubernetes_config_map_v1.vault_plugin_loader_script
    ]
  }
}