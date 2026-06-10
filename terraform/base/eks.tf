# VPC and EKS Module 
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source  = "app.terraform.io/rosemary-production/kubernetes/aws"
  version = "3.0.0"

  region                    = var.aws_region
  cluster_name              = var.project_name
  node_group_desired_size   = 3
  node_group_instance_types = ["t3.xlarge"]
}

import {
  id = "kube-system/aws-load-balancer-controller"
  to = module.kubernetes.helm_release.aws_load_balancer_controller
}