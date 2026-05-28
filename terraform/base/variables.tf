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

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use a single NAT Gateway for all private subnets"
  type        = bool
  default     = true
}

variable "cluster_version" {
  description = "Kubernetes version for EKS cluster (Auto Mode requires 1.33+)"
  type        = string
  default     = "1.35"

  validation {
    condition     = can(regex("^1\\.(3[3-9]|[4-9][0-9])$", var.cluster_version))
    error_message = "Cluster version must be 1.33 or higher for Auto Mode."
  }
}

# GPU Node Group Variables
variable "gpu_instance_types" {
  description = "List of GPU instance types for the node group"
  type        = list(string)
  default     = ["g5.xlarge"]

  validation {
    condition     = alltrue([for t in var.gpu_instance_types : can(regex("^(g[4-5]|p[3-4]|inf[1-2])\\.", t))])
    error_message = "GPU instance types must be from g4, g5, p3, p4, inf1, or inf2 families."
  }
}

variable "gpu_capacity_type" {
  description = "Capacity type for GPU nodes (ON_DEMAND or SPOT)"
  type        = string
  default     = "ON_DEMAND"

  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.gpu_capacity_type)
    error_message = "Capacity type must be ON_DEMAND or SPOT."
  }
}

variable "gpu_desired_size" {
  description = "Desired number of GPU nodes"
  type        = number
  default     = 1

  validation {
    condition     = var.gpu_desired_size >= 0
    error_message = "Desired size must be non-negative."
  }
}

variable "gpu_max_size" {
  description = "Maximum number of GPU nodes"
  type        = number
  default     = 3

  validation {
    condition     = var.gpu_max_size >= 1
    error_message = "Max size must be at least 1."
  }
}

variable "gpu_min_size" {
  description = "Minimum number of GPU nodes"
  type        = number
  default     = 0

  validation {
    condition     = var.gpu_min_size >= 0
    error_message = "Min size must be non-negative."
  }
}

variable "gpu_enable_taints" {
  description = "Enable taints on GPU nodes to prevent non-GPU workloads"
  type        = bool
  default     = true
}
