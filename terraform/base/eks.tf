

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

  # Enable IRSA (IAM Roles for Service Accounts)
  enable_irsa = true

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  # Enable EKS Auto Mode
  # Auto Mode automatically manages compute capacity
  compute_config = {
    enabled    = true
    node_pools = ["general-purpose", "system"]
  }

  # EKS Addons
  addons = {
    aws-efs-csi-driver = {
      most_recent              = true
      service_account_role_arn = aws_iam_role.efs_csi_driver.arn
    }
  }
}