# HCP HVN (HashiCorp Virtual Network)
resource "hcp_hvn" "main" {
  hvn_id         = "${var.project_name}-${var.environment}-hvn"
  cloud_provider = "aws"
  region         = var.aws_region
  cidr_block     = var.hvn_cidr
}

# HCP Vault Cluster
resource "hcp_vault_cluster" "main" {
  cluster_id      = "${var.project_name}-${var.environment}-vault"
  hvn_id          = hcp_hvn.main.hvn_id
  tier            = var.vault_tier
  public_endpoint = var.vault_public_endpoint
}

# HCP Vault Cluster Admin Token
resource "hcp_vault_cluster_admin_token" "main" {
  cluster_id = hcp_vault_cluster.main.cluster_id
}

# AWS VPC Peering Connection (AWS side)
resource "aws_vpc_peering_connection_accepter" "hcp" {
  vpc_peering_connection_id = hcp_aws_network_peering.main.provider_peering_id
  auto_accept               = true

  tags = {
    Name = "${var.project_name}-${var.environment}-hcp-peering"
  }
}

# HCP Network Peering
resource "hcp_aws_network_peering" "main" {
  hvn_id          = hcp_hvn.main.hvn_id
  peering_id      = "${var.project_name}-${var.environment}-peering"
  peer_vpc_id     = module.vpc.vpc_id
  peer_account_id = data.aws_caller_identity.current.account_id
  peer_vpc_region = var.aws_region
}

# Data source for AWS account ID
data "aws_caller_identity" "current" {}

# HVN Route to VPC
resource "hcp_hvn_route" "main" {
  hvn_link         = hcp_hvn.main.self_link
  hvn_route_id     = "${var.project_name}-${var.environment}-hvn-to-vpc"
  destination_cidr = module.vpc.vpc_cidr_block
  target_link      = hcp_aws_network_peering.main.self_link
}

# AWS Route from VPC to HVN (for private subnets)
resource "aws_route" "private_to_hvn" {
  count = length(module.vpc.private_route_table_ids)

  route_table_id            = module.vpc.private_route_table_ids[count.index]
  destination_cidr_block    = hcp_hvn.main.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.hcp.id
}

# AWS Route from VPC to HVN (for public subnets)
resource "aws_route" "public_to_hvn" {
  count = length(module.vpc.public_route_table_ids)

  route_table_id            = module.vpc.public_route_table_ids[count.index]
  destination_cidr_block    = hcp_hvn.main.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.hcp.id
}

# Security Group for Vault Access from EKS
resource "aws_security_group" "vault_access" {
  name_prefix = "${var.project_name}-${var.environment}-vault-access-"
  description = "Allow access to HCP Vault from EKS cluster"
  vpc_id      = module.vpc.vpc_id

  egress {
    description = "Allow HTTPS to HCP Vault"
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = [hcp_hvn.main.cidr_block]
  }

  egress {
    description = "Allow HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-vault-access"
  }
}

# Security Group Rule to allow HCP Vault to access EKS cluster
resource "aws_security_group_rule" "vault_to_eks" {
  type              = "ingress"
  description       = "Allow HCP Vault to communicate with EKS cluster"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [hcp_hvn.main.cidr_block]
  security_group_id = module.eks.cluster_security_group_id
}

# Additional rule for Vault agent injection webhook
resource "aws_security_group_rule" "vault_webhook_to_eks" {
  type              = "ingress"
  description       = "Allow HCP Vault webhook to communicate with EKS nodes"
  from_port         = 8200
  to_port           = 8200
  protocol          = "tcp"
  cidr_blocks       = [hcp_hvn.main.cidr_block]
  security_group_id = module.eks.cluster_security_group_id
}