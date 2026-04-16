data "http" "vault_cors" {
  url      = "${local.vault_endpoint}/v1/sys/config/cors"
  insecure = true
  method   = "POST"

  request_headers = {
    X-Vault-Token = var.vault_token
  }

  request_body = jsonencode({
    enabled = true,
    allowed_headers = [
      "Access-Control-Allow-Origin"
    ],
    allowed_origins = [
      "http://localhost:9000",
      local.vault_endpoint
    ]
  })
}