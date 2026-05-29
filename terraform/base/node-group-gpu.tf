# Get current AWS account ID
data "aws_caller_identity" "current" {}

# IAM Role for GPU Node Group
resource "aws_iam_role" "gpu_node_group" {
  name = "${var.project_name}-gpu-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-gpu-node-group-role"
  }
}

# Attach required policies to GPU node group role
resource "aws_iam_role_policy_attachment" "gpu_node_group_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.gpu_node_group.name
}

resource "aws_iam_role_policy_attachment" "gpu_node_group_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.gpu_node_group.name
}

resource "aws_iam_role_policy_attachment" "gpu_node_group_ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.gpu_node_group.name
}

resource "aws_iam_role_policy_attachment" "gpu_node_group_ssm_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.gpu_node_group.name
}

resource "aws_iam_role_policy_attachment" "gpu_node_group_security_compute_access" {
  policy_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/SecurityComputeAccess"
  role       = aws_iam_role.gpu_node_group.name
}

resource "aws_launch_template" "gpu_node_group" {
  name_prefix = "${var.project_name}-gpu-node-group-"

  vpc_security_group_ids = [module.kubernetes.node_security_group_id]

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${var.project_name}-gpu-node-group"
      Type = "gpu"
    }
  }
}

# GPU Node Group
resource "aws_eks_node_group" "gpu" {
  cluster_name    = module.kubernetes.cluster_name
  node_group_name = "${var.project_name}-gpu-node-group"
  node_role_arn   = aws_iam_role.gpu_node_group.arn
  subnet_ids      = module.kubernetes.private_subnets
  version         = var.cluster_version

  launch_template {
    id      = aws_launch_template.gpu_node_group.id
    version = aws_launch_template.gpu_node_group.latest_version
  }

  # GPU instance types - g5 family for NVIDIA A10G GPUs
  instance_types = var.gpu_instance_types

  # AMI type for GPU instances
  ami_type = "AL2023_x86_64_NVIDIA"

  # Capacity type
  capacity_type = var.gpu_capacity_type

  scaling_config {
    desired_size = var.gpu_desired_size
    max_size     = var.gpu_max_size
    min_size     = var.gpu_min_size
  }

  update_config {
    max_unavailable = 1
  }

  # Labels for GPU scheduling
  labels = {
    "workload-type"          = "gpu"
    "nvidia.com/gpu"         = "true"
    "node.kubernetes.io/gpu" = "true"
  }

  # Taints to ensure only GPU workloads are scheduled
  dynamic "taint" {
    for_each = var.gpu_enable_taints ? [1] : []
    content {
      key    = "nvidia.com/gpu"
      value  = "true"
      effect = "NO_SCHEDULE"
    }
  }

  tags = {
    Name = "${var.project_name}-gpu-node-group"
    Type = "gpu"
  }

  # Ensure IAM role policies are attached before creating node group
  depends_on = [
    aws_iam_role_policy_attachment.gpu_node_group_worker_policy,
    aws_iam_role_policy_attachment.gpu_node_group_cni_policy,
    aws_iam_role_policy_attachment.gpu_node_group_ecr_policy,
    aws_iam_role_policy_attachment.gpu_node_group_ssm_policy,
    aws_iam_role_policy_attachment.gpu_node_group_security_compute_access,
  ]

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [scaling_config[0].desired_size]
  }
}

# NVIDIA Device Plugin via Helm
# This enables GPU scheduling in Kubernetes
resource "helm_release" "nvidia_device_plugin" {
  name             = "nvdp"
  repository       = "https://nvidia.github.io/k8s-device-plugin"
  chart            = "nvidia-device-plugin"
  namespace        = "nvidia"
  create_namespace = true

  set = [{
    name  = "gfd.enabled"
    value = "true"
  }]

  depends_on = [aws_eks_node_group.gpu]
}

import {
  id = "nvidia/nvdp"
  to = helm_release.nvidia_device_plugin
}