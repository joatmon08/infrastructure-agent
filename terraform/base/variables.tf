variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "infrastructure-agent"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "cluster_version" {
  description = "Kubernetes version for EKS cluster (Auto Mode requires 1.33+)"
  type        = string
  default     = "1.36"

  validation {
    condition     = can(regex("^1\\.(3[3-9]|[4-9][0-9])$", var.cluster_version))
    error_message = "Cluster version must be 1.33 or higher for Auto Mode."
  }
}

variable "inbound_cidrs_for_lbs" {
  description = "CIDR blocks allowed to access load balancers"
  type        = list(string)
  default     = []
}

variable "inbound_cidrs_for_kubernetes" {
  description = "CIDR blocks allowed to access Kubernetes cluster endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
  default     = null
}

variable "node_group_min_size" {
  description = "Minimum size of node group"
  type        = number
  default     = 1
}

variable "node_group_max_size" {
  description = "Maximum size of node group"
  type        = number
  default     = 5
}

variable "node_group_desired_size" {
  description = "Desired size of node group"
  type        = number
  default     = 4
}

variable "node_group_instance_types" {
  description = "Instance types for node group"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "aws_load_balancer_controller_helm_chart_version" {
  description = "Helm chart version for AWS Load Balancer Controller"
  type        = string
  default     = "3.5.0"
}


variable "gpu_instance_types" {
  description = "Instance types for the GPU node group"
  type        = list(string)
  default     = ["g4dn.xlarge"]
}

variable "gpu_capacity_type" {
  description = "Capacity type for GPU node group (ON_DEMAND or SPOT)"
  type        = string
  default     = "ON_DEMAND"
}

variable "gpu_desired_size" {
  description = "Desired number of GPU nodes"
  type        = number
  default     = 1
}

variable "gpu_max_size" {
  description = "Maximum number of GPU nodes"
  type        = number
  default     = 2
}

variable "gpu_min_size" {
  description = "Minimum number of GPU nodes"
  type        = number
  default     = 1
}

variable "gpu_enable_taints" {
  description = "Whether to taint GPU nodes with nvidia.com/gpu=true:NoSchedule"
  type        = bool
  default     = true
}
