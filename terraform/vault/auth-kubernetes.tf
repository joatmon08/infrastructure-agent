data "kubernetes_service_account_v1" "vault_auth" {
  metadata {
    name      = data.terraform_remote_state.kubernetes.outputs.helm_vault_name
    namespace = data.terraform_remote_state.kubernetes.outputs.helm_vault_namespace
  }
}

resource "kubernetes_secret_v1" "vault_auth" {
  metadata {
    name      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
    namespace = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    annotations = {
      "kubernetes.io/service-account.name"      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
      "kubernetes.io/service-account.namespace" = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = data.terraform_remote_state.kubernetes.outputs.cluster_endpoint
  kubernetes_ca_cert     = kubernetes_secret_v1.vault_auth.data["ca.crt"]
  token_reviewer_jwt     = kubernetes_secret_v1.vault_auth.data.token
  disable_iss_validation = "true"
}