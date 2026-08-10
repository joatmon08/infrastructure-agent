data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, length(var.private_subnet_cidrs))

  # Default security group rules for EKS nodes (cryptominer remediation)
  # These rules restrict egress to only necessary ports and destinations
  default_node_security_group_rules = {
    egress_https_vpc = {
      description = "Allow HTTPS to VPC CIDR for internal services"
      type        = "egress"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
    }
    egress_8080_vpc = {
      description = "Allow port 8080 to VPC CIDR for internal applications"
      type        = "egress"
      from_port   = 8080
      to_port     = 8080
      protocol    = "tcp"
      cidr_blocks = [var.vpc_cidr]
    }
    egress_dns = {
      description = "Allow DNS queries"
      type        = "egress"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = [var.vpc_cidr]
    }
    egress_ntp = {
      description = "Allow NTP for time synchronization"
      type        = "egress"
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
    egress_https_internet = {
      description = "Allow HTTPS to internet for ECR, updates, etc."
      type        = "egress"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
    egress_http_internet = {
      description = "Allow HTTP to internet for package repositories"
      type        = "egress"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  node_security_group_rules = local.default_node_security_group_rules
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.6"

  name = "${var.project_name}-vpc"
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway   = var.enable_nat_gateway
  single_nat_gateway   = var.single_nat_gateway
  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = {
    "kubernetes.io/cluster/${var.project_name}" = "shared"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.24"

  name               = var.project_name
  kubernetes_version = var.cluster_version

  endpoint_public_access       = true
  endpoint_public_access_cidrs = length(var.inbound_cidrs_for_lbs) > 0 ? var.inbound_cidrs_for_lbs : ["0.0.0.0/0"]

  create_cloudwatch_log_group = false

  addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      before_compute = true
      most_recent    = true
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = aws_iam_role.ebs_csi_driver.arn
    }
    aws-efs-csi-driver = {
      most_recent              = true
      service_account_role_arn = aws_iam_role.efs_csi_driver.arn
    }
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  node_security_group_additional_rules = local.node_security_group_rules

  # eks_managed_node_groups = {
  #   default_amd64 = {
  #     name = "amd64"

  #     ami_type       = "AL2023_x86_64_STANDARD"
  #     instance_types = ["t3.xlarge"]

  #     min_size     = 3
  #     max_size     = 6
  #     desired_size = 3

  #     iam_role_additional_policies = {
  #       AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  #       AmazonEKS_CNI_Policy         = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  #       ECRReadOnly                  = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  #       SecurityComputeAccess        = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/SecurityComputeAccess"
  #     }

  #     subnet_ids = module.vpc.private_subnets

  #     tags = {
  #       NodeGroup = "default-amd64"
  #     }
  #   }
  # }

  enable_cluster_creator_admin_permissions = true

  tags = {
    Cluster = var.project_name
  }
}

# ── EBS CSI Driver IRSA ────────────────────────────────────────────────────────

data "aws_iam_policy_document" "ebs_csi_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ebs_csi_driver" {
  name               = "${var.project_name}-ebs-csi-driver"
  assume_role_policy = data.aws_iam_policy_document.ebs_csi_assume_role.json
  tags               = { Component = "ebs-csi-driver" }
}

data "aws_iam_policy_document" "ebs_csi" {
  statement {
    actions = [
      "ec2:DescribeAvailabilityZones", "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstances", "ec2:DescribeSnapshots",
      "ec2:DescribeTags", "ec2:DescribeVolumes", "ec2:DescribeVolumesModifications",
    ]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:CreateSnapshot", "ec2:ModifyVolume"]
    resources = ["arn:aws:ec2:*:*:volume/*"]
  }
  statement {
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume"]
    resources = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:instance/*"]
  }
  statement {
    actions   = ["ec2:CreateVolume", "ec2:EnableFastSnapshotRestores"]
    resources = ["arn:aws:ec2:*:*:snapshot/*"]
  }
  statement {
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateVolume", "CreateSnapshot"]
    }
  }
  statement {
    actions   = ["ec2:DeleteTags"]
    resources = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"]
  }
  statement {
    actions   = ["ec2:CreateVolume"]
    resources = ["arn:aws:ec2:*:*:volume/*"]
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["ec2:DeleteVolume"]
    resources = ["arn:aws:ec2:*:*:volume/*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/ebs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["arn:aws:ec2:*:*:snapshot/*"]
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/CSIVolumeSnapshotName"
      values   = ["*"]
    }
  }
}

resource "aws_iam_policy" "ebs_csi" {
  name   = "${var.project_name}-ebs-csi-driver"
  policy = data.aws_iam_policy_document.ebs_csi.json
}

resource "aws_iam_role_policy_attachment" "ebs_csi" {
  role       = aws_iam_role.ebs_csi_driver.name
  policy_arn = aws_iam_policy.ebs_csi.arn
}

# ── EFS CSI Driver IRSA ────────────────────────────────────────────────────────

data "aws_iam_policy_document" "efs_csi_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:kube-system:efs-csi-controller-sa"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "efs_csi_driver" {
  name               = "${var.project_name}-efs-csi-driver"
  assume_role_policy = data.aws_iam_policy_document.efs_csi_assume_role.json
  tags               = { Component = "efs-csi-driver" }
}

data "aws_iam_policy_document" "efs_csi" {
  statement {
    actions = [
      "ec2:DescribeAvailabilityZones",
      "elasticfilesystem:DescribeAccessPoints",
      "elasticfilesystem:DescribeFileSystems",
      "elasticfilesystem:DescribeMountTargets",
    ]
    resources = ["*"]
  }
  statement {
    actions   = ["elasticfilesystem:CreateAccessPoint"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/efs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["elasticfilesystem:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/efs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["elasticfilesystem:DeleteAccessPoint"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/efs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "efs_csi" {
  name   = "${var.project_name}-efs-csi-driver"
  policy = data.aws_iam_policy_document.efs_csi.json
}

resource "aws_iam_role_policy_attachment" "efs_csi" {
  role       = aws_iam_role.efs_csi_driver.name
  policy_arn = aws_iam_policy.efs_csi.arn
}

# ── gp3 default StorageClass ───────────────────────────────────────────────────

resource "kubernetes_storage_class_v1" "ebs_sc" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  storage_provisioner = "ebs.csi.aws.com"
  reclaim_policy      = "Delete"
  volume_binding_mode = "Immediate"
  parameters = {
    type = "gp3"
  }
}

# ── AWS Load Balancer Controller IRSA + Helm ───────────────────────────────────

data "aws_iam_policy_document" "alb_controller_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.eks.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "alb_controller" {
  name               = "${var.project_name}-alb-controller"
  assume_role_policy = data.aws_iam_policy_document.alb_controller_assume_role.json
  tags               = { Component = "aws-load-balancer-controller" }
}

data "aws_iam_policy_document" "alb_controller" {
  statement {
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.amazonaws.com"]
    }
  }
  statement {
    actions = [
      "ec2:DescribeAccountAttributes", "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones", "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs", "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags", "ec2:GetCoipPoolUsage", "ec2:DescribeCoipPools",
      "ec2:GetSecurityGroupsForVpc", "ec2:DescribeIpamPools", "ec2:DescribeRouteTables",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeTrustStores",
      "elasticloadbalancing:DescribeListenerAttributes",
      "elasticloadbalancing:DescribeCapacityReservation",
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "cognito-idp:DescribeUserPoolClient", "acm:ListCertificates",
      "acm:DescribeCertificate", "iam:ListServerCertificates", "iam:GetServerCertificate",
      "waf-regional:GetWebACL", "waf-regional:GetWebACLForResource",
      "waf-regional:AssociateWebACL", "waf-regional:DisassociateWebACL",
      "wafv2:GetWebACL", "wafv2:GetWebACLForResource",
      "wafv2:AssociateWebACL", "wafv2:DisassociateWebACL",
      "shield:GetSubscriptionState", "shield:DescribeProtection",
      "shield:CreateProtection", "shield:DeleteProtection",
    ]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:CreateSecurityGroup"]
    resources = ["*"]
  }
  statement {
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup"]
    }
    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["ec2:CreateTags", "ec2:DeleteTags"]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:DeleteSecurityGroup"]
    resources = ["*"]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateTargetGroup"]
    resources = ["*"]
    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["elasticloadbalancing:CreateListener", "elasticloadbalancing:DeleteListener", "elasticloadbalancing:CreateRule", "elasticloadbalancing:DeleteRule"]
    resources = ["*"]
  }
  statement {
    actions   = ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"]
    resources = ["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*", "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*", "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"]
    resources = ["arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*", "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*", "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*", "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"]
  }
  statement {
    actions   = ["elasticloadbalancing:ModifyLoadBalancerAttributes", "elasticloadbalancing:SetIpAddressType", "elasticloadbalancing:SetSecurityGroups", "elasticloadbalancing:SetSubnets", "elasticloadbalancing:DeleteLoadBalancer", "elasticloadbalancing:ModifyTargetGroup", "elasticloadbalancing:ModifyTargetGroupAttributes", "elasticloadbalancing:DeleteTargetGroup", "elasticloadbalancing:ModifyListenerAttributes", "elasticloadbalancing:ModifyCapacityReservation", "elasticloadbalancing:ModifyIpPools"]
    resources = ["*"]
    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["elasticloadbalancing:RegisterTargets", "elasticloadbalancing:DeregisterTargets"]
    resources = ["arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"]
  }
  statement {
    actions   = ["elasticloadbalancing:SetWebAcl", "elasticloadbalancing:ModifyListener", "elasticloadbalancing:AddListenerCertificates", "elasticloadbalancing:RemoveListenerCertificates", "elasticloadbalancing:ModifyRule", "elasticloadbalancing:SetRulePriorities"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "alb_controller" {
  name   = "${var.project_name}-alb-controller"
  policy = data.aws_iam_policy_document.alb_controller.json
}

resource "aws_iam_role_policy_attachment" "alb_controller" {
  role       = aws_iam_role.alb_controller.name
  policy_arn = aws_iam_policy.alb_controller.arn
}

resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "3.2.2"

  set = [
    { name = "clusterName", value = module.eks.cluster_name },
    { name = "region", value = var.aws_region },
    { name = "vpcId", value = module.vpc.vpc_id },
    { name = "serviceAccount.create", value = "true" },
    { name = "serviceAccount.name", value = "aws-load-balancer-controller" },
    { name = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn", value = aws_iam_role.alb_controller.arn },
    { name = "defaultLoadBalancerScheme", value = "internet-facing" },
  ]

  depends_on = [module.eks, aws_iam_role_policy_attachment.alb_controller]
}
