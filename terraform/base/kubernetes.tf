resource "kubernetes_storage_class_v1" "auto_mode" {
  metadata {
    name = "auto-ebs-sc"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  storage_provisioner = "ebs.csi.eks.amazonaws.com"
  reclaim_policy      = "Delete"
  volume_binding_mode = "WaitForFirstConsumer"
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }
}

resource "helm_release" "vault" {
  name             = "vault"
  namespace        = var.kubernetes_namespace_vault
  create_namespace = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = var.vault_helm_chart_version

  values = [templatefile("templates/vault.yaml.tpl", {
    LOAD_BALANCER_SOURCE_RANGES = concat(var.inbound_cidrs_for_lbs, [var.vpc_cidr]),
    VAULT_CERTIFICATE_ARN       = aws_acm_certificate.vault.arn
    AWS_REGION                  = var.aws_region
    KMS_KEY_ID                  = aws_kms_key.vault.id
    VAULT_IAM_ROLE_ARN          = aws_iam_role.vault.arn
  })]

  depends_on = [
    kubernetes_storage_class_v1.auto_mode,
    aws_iam_role_policy_attachment.vault_kms
  ]
}