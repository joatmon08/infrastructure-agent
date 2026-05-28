resource "helm_release" "vault" {
  name             = "vault"
  namespace        = kubernetes_namespace_v1.vault.metadata[0].name
  create_namespace = false

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
    kubernetes_secret_v1.vault_tls_server
  ]
}

data "kubernetes_service_v1" "vault" {
  metadata {
    name      = "${helm_release.vault.name}-ui"
    namespace = helm_release.vault.namespace
  }
}

resource "kubernetes_ingress_v1" "vault_ui" {
  metadata {
    name      = "vault-ui"
    namespace = kubernetes_namespace_v1.vault.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path" = "/v1/sys/health"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = var.allow_hcp_terraform_to_access_vault ? "0.0.0.0/0" : "${join(",", concat(var.inbound_cidrs_for_lbs, [data.terraform_remote_state.base.outputs.vpc_cidr_block]))}"
      "alb.ingress.kubernetes.io/success-codes"    = "200,204"
      "alb.ingress.kubernetes.io/tags"             = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
      "alb.ingress.kubernetes.io/backend-protocol" = "HTTPS"
      "alb.ingress.kubernetes.io/listen-ports"     = "[{\"HTTPS\":443}]"
      "alb.ingress.kubernetes.io/certificate-arn"  = "${aws_acm_certificate.vault.arn}"
    }
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        path {
          backend {
            service {
              name = data.kubernetes_service_v1.vault.metadata[0].name
              port {
                number = 8200
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }
      }
    }
  }

  depends_on = [
    helm_release.vault
  ]
}