resource "helm_release" "vault" {
  name             = "vault"
  namespace        = var.kubernetes_namespace_vault
  create_namespace = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = var.vault_helm_chart_version

  values = [templatefile("${path.module}/templates/vault.yaml.tpl", {
    LOAD_BALANCER_SOURCE_RANGES = var.allow_hcp_terraform_to_access_vault ? ["0.0.0.0/0"] : concat(var.inbound_cidrs_for_lbs, [data.terraform_remote_state.base.outputs.vpc_cidr_block]),
    AWS_REGION                  = var.aws_region
    KMS_KEY_ID                  = aws_kms_key.vault.key_id
    VAULT_IAM_ROLE_ARN          = aws_iam_role.vault.arn
    VAULT_VERSION               = var.vault_version
    VAULT_PLUGINS_PVC_NAME      = kubernetes_persistent_volume_claim_v1.vault_plugins.metadata[0].name
  })]

  depends_on = [
    kubernetes_storage_class_v1.auto_mode,
    kubernetes_secret_v1.vault_tls_server
  ]
}

data "kubernetes_service_v1" "vault" {
  metadata {
    name      = "${helm_release.vault.name}-ui"
    namespace = helm_release.vault.namespace
  }
}