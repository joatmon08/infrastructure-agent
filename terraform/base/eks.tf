# VPC and EKS Module 
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source  = "app.terraform.io/rosemary-production/kubernetes/aws"
  version = "2.0.2"

  region                    = var.aws_region
  cluster_name              = var.project_name
  node_group_desired_size   = 3
  node_group_instance_types = ["t3.xlarge"]
}

import {
  id = "kube-system/aws-load-balancer-controller"
  to = module.kubernetes.helm_release.aws_load_balancer_controller
}

resource "aws_vpc_security_group_ingress_rule" "webhook" {
  security_group_id = module.kubernetes.node_security_group_id

  cidr_ipv4   = module.vpc.vpc_cidr_block
  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

resource "aws_vpc_security_group_ingress_rule" "vault_webhook" {
  security_group_id = module.kubernetes.node_security_group_id

  cidr_ipv4   = module.vpc.vpc_cidr_block
  from_port   = 8080
  ip_protocol = "tcp"
  to_port     = 8080
}