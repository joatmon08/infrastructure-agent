resource "vault_auth_backend" "userpass" {
  type = "userpass"
}

# Enable KV v2 secrets engine for storing credentials
resource "vault_mount" "credentials" {
  path        = "credentials"
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 secrets engine for storing user credentials"
}

ephemeral "random_password" "end_user" {
  length  = 16
  special = false
}

# Store the password in Vault KV store using write-only attribute
resource "vault_kv_secret_v2" "end_user_password" {
  mount = vault_mount.credentials.path
  name  = "end-user"
  data_json_wo = jsonencode({
    username = local.end_user
    password = ephemeral.random_password.end_user.result
  })
}

data "vault_kv_secret_v2" "end_user_password" {
  mount = vault_kv_secret_v2.end_user_password.mount
  name  = vault_kv_secret_v2.end_user_password.name
}

resource "vault_generic_endpoint" "end_user" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${local.end_user}"
  ignore_absent_fields = true
  data_json            = <<EOT
{
  "token_policies": ["${vault_policy.agent_oidc_authorize.name}"],
  "token_ttl": "1h",
  "password": "${data.vault_kv_secret_v2.end_user_password.data.password}"
}
EOT
}

resource "vault_identity_entity" "end_user" {
  name = local.end_user
}

resource "vault_identity_entity_alias" "end_user" {
  name           = local.end_user
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.end_user.id
}