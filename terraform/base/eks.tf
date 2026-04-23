# VPC and EKS Module from GitHub
# This module creates both VPC and EKS cluster resources
module "kubernetes" {
  source = "github.com/joatmon08/terraform-aws-kubernetes"

  region       = var.aws_region
  cluster_name = var.project_name
}