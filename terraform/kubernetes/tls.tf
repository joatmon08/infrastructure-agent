resource "aws_acm_certificate" "vault" {
  private_key       = base64decode(var.vault_server_certificate_key)
  certificate_body  = base64decode(var.vault_server_certificate)
  certificate_chain = "${base64decode(var.vault_server_certificate)}\n${base64decode(var.vault_server_ca_certificate)}"
}

resource "kubernetes_secret_v1" "vault_tls_server" {
  metadata {
    name      = "tls-server"
    namespace = helm_release.vault.namespace
  }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = base64decode(var.vault_server_certificate)
    "tls.key" = base64decode(var.vault_server_certificate_key)
    "ca.crt"  = base64decode(var.vault_server_ca_certificate)
  }
}