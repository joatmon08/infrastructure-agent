locals {

  # Default security group rules for EKS nodes (cryptominer remediation)
  # These rules restrict egress to only necessary ports and destinations
  node_security_group_rules = {
    # Allow HTTPS to VPC for internal services
    egress_https_vpc = {
      description = "Allow HTTPS to VPC CIDR for internal services"
      type        = "egress"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
    }

    # Allow port 8080 within VPC for legitimate applications (blocks external mining pools)
    egress_8080_vpc = {
      description = "Allow port 8080 to VPC CIDR for internal applications"
      type        = "egress"
      from_port   = 8080
      to_port     = 8080
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
    }

    # Allow DNS queries within VPC
    egress_dns = {
      description = "Allow DNS queries"
      type        = "egress"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = [var.vpc_cidr]
    }

    # Allow NTP for time synchronization
    egress_ntp = {
      description = "Allow NTP for time synchronization"
      type        = "egress"
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }

    # Allow HTTPS to internet for pulling images and updates
    egress_https_internet = {
      description = "Allow HTTPS to internet for ECR, updates, etc."
      type        = "egress"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }

    # Allow HTTP to internet (needed for some package repositories)
    egress_http_internet = {
      description = "Allow HTTP to internet for package repositories"
      type        = "egress"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  subnets = cidrsubnets(var.vpc_cidr, 8, 8, 8, 8, 8, 8, 8, 8, 8)
}
