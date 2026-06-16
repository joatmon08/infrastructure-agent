# Service account for Vault Secrets Operator
resource "kubernetes_service_account_v1" "vault_secrets_operator" {
  metadata {
    name      = "vault-secrets-operator"
    namespace = kubernetes_namespace_v1.vault.metadata[0].name
    labels = {
      app = "vault-secrets-operator"
    }
  }
}

# Vault Secrets Operator Helm Release
resource "helm_release" "vault_secrets_operator" {
  name             = "vault-secrets-operator"
  namespace        = kubernetes_namespace_v1.vault.metadata[0].name
  create_namespace = false

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault-secrets-operator"
  version    = var.vault_secrets_operator_version

  values = [
    yamlencode({
      defaultVaultConnection = {
        enabled       = true
        address       = "https://vault.${kubernetes_namespace_v1.vault.metadata[0].name}.svc.cluster.local:8200"
        skipTLSVerify = true
      }
      defaultAuthMethod = {
        enabled = true
        method  = "kubernetes"
        mount   = "kubernetes"
        kubernetes = {
          role           = "vault-secrets-operator"
          serviceAccount = kubernetes_service_account_v1.vault_secrets_operator.metadata[0].name
        }
      }
    })
  ]

  depends_on = [
    helm_release.vault,
    kubernetes_service_account_v1.vault_secrets_operator
  ]
}