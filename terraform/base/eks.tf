# VPC and EKS Module
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source  = "app.terraform.io/rosemary-production/kubernetes/aws"
  version = "3.0.0"

  region                          = var.aws_region
  cluster_name                    = var.project_name
  node_group_desired_size         = 3
  node_group_instance_types       = ["t3.xlarge"]
  enable_guardduty_eks_protection = false
}

# Import existing CloudWatch log group created by EKS
import {
  id = "/aws/eks/infra-agent/cluster"
  to = module.kubernetes.aws_cloudwatch_log_group.eks_cluster
}

# Note: GuardDuty EKS protection is disabled (enable_guardduty_eks_protection = false)
# because it's managed by another team via Service Control Policy

# import {
#   id = "kube-system/aws-load-balancer-controller"
#   to = module.kubernetes.helm_release.aws_load_balancer_controller
# }