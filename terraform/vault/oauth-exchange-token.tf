resource "vault_generic_endpoint" "sts" {
  path                 = "sys/mounts/${var.oauth_token_exchange_secrets_path}"
  ignore_absent_fields = true

  data_json = <<EOT
{
  "type": "vault-plugin-secrets-oauth-token-exchange"
}
EOT
}

