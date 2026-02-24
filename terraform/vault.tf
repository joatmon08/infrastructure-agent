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
  })]
}