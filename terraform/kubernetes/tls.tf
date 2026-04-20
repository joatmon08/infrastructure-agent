# Root CA
resource "tls_private_key" "vault_key" {
  algorithm = "RSA"
  rsa_bits  = 2048 # must be 2048 to work with ACM
}

resource "tls_cert_request" "vault" {
  private_key_pem = tls_private_key.vault_key.private_key_pem

  subject {
    common_name  = "system:node:*.${var.kubernetes_namespace_vault}.svc.cluster.local"
    organization = "system:nodes"
  }

  dns_names = [
    "*.vault-internal",
    "*.vault-internal.${var.kubernetes_namespace_vault}.svc.cluster.local",
    "*.${var.kubernetes_namespace_vault}"
  ]

  ip_addresses = [
    "127.0.0.1",
  ]
}

resource "kubernetes_certificate_signing_request_v1" "vault" {
  metadata {
    name = "vault.svc"
  }

  spec {
    signer_name = "beta.eks.amazonaws.com/app-serving"

    expiration_seconds = 8640000

    request = tls_cert_request.vault.cert_request_pem

    usages = [
      "digital signature",
      "key encipherment",
      "server auth"
    ]
  }

  auto_approve = true
}

resource "kubernetes_secret_v1" "vault_tls_server" {
  metadata {
    name      = "tls-server"
    namespace = kubernetes_namespace_v1.vault.metadata[0].name
  }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = kubernetes_certificate_signing_request_v1.vault.certificate
    "tls.key" = tls_private_key.vault_key.private_key_pem
    "ca.crt"  = base64decode(data.terraform_remote_state.base.outputs.cluster_certificate_authority_data)
  }
}

resource "aws_acm_certificate" "vault" {
  private_key       = tls_private_key.vault_key.private_key_pem
  certificate_body  = kubernetes_certificate_signing_request_v1.vault.certificate
  certificate_chain = "${kubernetes_certificate_signing_request_v1.vault.certificate}\n${base64decode(data.terraform_remote_state.base.outputs.cluster_certificate_authority_data)}"
}