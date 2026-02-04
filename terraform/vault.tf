resource "helm_release" "vault" {
  name             = "vault"
  namespace        = "vault"
  create_namespace = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"
  version    = var.vault_helm_chart_version

  set = [{
    name  = "injector.externalVaultAddr"
    value = hcp_vault_cluster.main.vault_private_endpoint_url
  }]
}


data "kubernetes_service_account_v1" "vault_auth" {
  metadata {
    name      = "vault"
    namespace = "vault"
  }
}

resource "kubernetes_secret_v1" "vault_auth" {
  depends_on = [helm_release.vault]
  metadata {
    name      = "vault"
    namespace = "vault"
    annotations = {
      "kubernetes.io/service-account.name"      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
      "kubernetes.io/service-account.namespace" = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_auth_backend" "kubernetes" {
  depends_on = [helm_release.vault]
  type       = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  depends_on             = [helm_release.vault]
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = module.eks.cluster_endpoint
  kubernetes_ca_cert     = kubernetes_secret_v1.vault_auth.data["ca.crt"]
  token_reviewer_jwt     = kubernetes_secret_v1.vault_auth.data.token
  disable_iss_validation = "true"
}

resource "vault_identity_oidc_client" "agent" {
  name = "agent"
  redirect_uris = [
    "http://127.0.0.1:9999/callback"
  ]
  assignments = [
    "allow_all"
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
}

resource "vault_identity_oidc_provider" "agent" {
  name          = "agent"
  https_enabled = true
  issuer_host   = replace(hcp_vault_cluster.main.vault_public_endpoint_url, "https://", "")
  allowed_client_ids = [
    vault_identity_oidc_client.agent.client_id
  ]
}