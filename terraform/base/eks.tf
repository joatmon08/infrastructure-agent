# VPC and EKS Module
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source  = "app.terraform.io/rosemary-production/kubernetes/aws"
  version = "4.0.0"

  region                               = var.aws_region
  cluster_name                         = var.project_name
  node_group_desired_size              = 3
  node_group_instance_types            = ["t3.xlarge"]
  cluster_endpoint_public_access_cidrs = var.inbound_cidrs_for_lbs
}
