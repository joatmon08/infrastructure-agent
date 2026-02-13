# Root CA
resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 2048 # must be 2048 to work with ACM
}

resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem   = tls_private_key.ca_key.private_key_pem
  is_ca_certificate = true

  subject {
    common_name = "ca.${var.server_tls_servername}"
  }

  validity_period_hours = 8760

  allowed_uses = [
    "cert_signing",
    "crl_signing"
  ]
}

# Server Certificate
resource "tls_private_key" "server_key" {
  algorithm = "RSA"
  rsa_bits  = 2048 # must be 2048 to work with ACM
}

## Public Server Cert
resource "tls_cert_request" "server_cert" {
  private_key_pem = tls_private_key.server_key.private_key_pem

  subject {
    common_name = var.server_tls_servername
  }

  dns_names = [
    var.server_tls_servername,
    "localhost"
  ]

  ip_addresses = ["127.0.0.1"]
}

## Signed Public Server Certificate
resource "tls_locally_signed_cert" "server_signed_cert" {
  cert_request_pem = tls_cert_request.server_cert.cert_request_pem

  ca_private_key_pem = tls_private_key.ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca_cert.cert_pem

  allowed_uses = [
    "client_auth",
    "digital_signature",
    "key_agreement",
    "key_encipherment",
    "server_auth",
  ]

  validity_period_hours = 8760
}

resource "aws_acm_certificate" "vault" {
  private_key       = tls_private_key.server_key.private_key_pem
  certificate_body  = tls_locally_signed_cert.server_signed_cert.cert_pem
  certificate_chain = tls_self_signed_cert.ca_cert.cert_pem
}

resource "kubernetes_secret_v1" "vault_tls_server" {
  metadata {
    name      = "tls-server"
    namespace = helm_release.vault.namespace
  }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = tls_locally_signed_cert.server_signed_cert.cert_pem
    "tls.key" = tls_private_key.server_key.private_key_pem
    "ca.crt"  = tls_self_signed_cert.ca_cert.cert_pem
  }
}