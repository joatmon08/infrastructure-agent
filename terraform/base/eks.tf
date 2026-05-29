# VPC and EKS Module 
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source  = "app.terraform.io/rosemary-production/kubernetes/aws"
  version = "2.0.2"

  region       = var.aws_region
  cluster_name = var.project_name
}

import {
  id = "kube-system/aws-load-balancer-controller"
  to = module.kubernetes.helm_release.aws_load_balancer_controller
}