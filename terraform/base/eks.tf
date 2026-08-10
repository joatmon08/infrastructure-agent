module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.24"

  name               = var.project_name
  kubernetes_version = var.cluster_version

  endpoint_public_access       = true
  endpoint_public_access_cidrs = var.inbound_cidrs_for_kubernetes

  # Enable all control plane logging types
  enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  create_cloudwatch_log_group = false

  addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      before_compute = true
      most_recent    = true
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_driver_irsa.arn
    }

    aws-efs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.efs_csi_driver_irsa.arn
    }
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  node_security_group_additional_rules = local.node_security_group_rules

  eks_managed_node_groups = {
    default_amd64 = {
      name = "amd64"

      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = var.node_group_instance_types

      min_size     = var.node_group_min_size
      max_size     = var.node_group_max_size
      desired_size = var.node_group_desired_size

      subnet_ids = module.vpc.private_subnets

      tags = {
        NodeGroup = "default-amd64"
      }
    }
  }

  enable_cluster_creator_admin_permissions = true

  tags = {
    Cluster = var.project_name
  }
}

module "efs_csi_driver_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.8"

  name = "${var.project_name}-efs-csi-driver"

  use_name_prefix = true

  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }

  tags = {
    Component = "efs-csi-driver"
    Cluster   = var.project_name
  }
}

module "ebs_csi_driver_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.8"

  name = "${var.project_name}-ebs-csi-driver"

  use_name_prefix = true

  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }

  tags = {
    Component = "ebs-csi-driver"
    Cluster   = var.project_name
  }
}

resource "kubernetes_storage_class_v1" "ebs_sc" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  storage_provisioner = "ebs.csi.aws.com"
  reclaim_policy      = "Delete"
  volume_binding_mode = "Immediate"
  parameters = {
    type = "gp3"
  }
}

module "aws_load_balancer_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.8"

  name = "${var.project_name}-alb-controller"

  use_name_prefix = true

  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = {
    Component = "aws-load-balancer-controller"
    Cluster   = var.project_name
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = var.aws_load_balancer_controller_helm_chart_version

  values = [templatefile("${path.module}/templates/alb-values.yaml", {
    cluster_name = module.eks.cluster_name
    region       = var.aws_region
    vpc_id       = module.vpc.vpc_id
    role_arn     = module.aws_load_balancer_controller_irsa.arn
    subnet_ids   = jsonencode(module.vpc.public_subnets)
  })]

  depends_on = [
    module.eks,
    module.aws_load_balancer_controller_irsa
  ]
}
