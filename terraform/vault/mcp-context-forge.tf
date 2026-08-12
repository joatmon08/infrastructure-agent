########################################################################
# KV v2 secrets engine for MCP Context Forge
########################################################################

resource "vault_mount" "mcp_context_forge" {
  path        = "mcp-context-forge"
  type        = "kv"
  options     = { version = "2" }
  description = "KV v2 secrets engine for MCP Context Forge credentials"
}

########################################################################
# Secrets stored in Vault
########################################################################

ephemeral "random_password" "mcp_postgres_password" {
  length  = 16
  special = false
}

ephemeral "random_password" "mcp_admin_password" {
  length  = 24
  special = false
}

ephemeral "random_password" "mcp_default_user_password" {
  length  = 24
  special = false
}

ephemeral "random_password" "mcp_basic_auth_password" {
  length  = 24
  special = false
}

resource "vault_kv_secret_v2" "mcp_postgres" {
  mount = vault_mount.mcp_context_forge.path
  name  = "postgres"

  data_json_wo = jsonencode({
    POSTGRES_USER     = "mcpuser"
    POSTGRES_PASSWORD = ephemeral.random_password.mcp_postgres_password.result
    POSTGRES_DB       = "postgresdb"
  })
  data_json_wo_version = 2
}

resource "vault_kv_secret_v2" "mcp_app" {
  mount = vault_mount.mcp_context_forge.path
  name  = "app"

  data_json_wo = jsonencode({
    PLATFORM_ADMIN_PASSWORD = ephemeral.random_password.mcp_admin_password.result
    DEFAULT_USER_PASSWORD   = ephemeral.random_password.mcp_default_user_password.result
    BASIC_AUTH_PASSWORD     = ephemeral.random_password.mcp_basic_auth_password.result
    JWT_SECRET_KEY          = var.mcp_context_forge_jwt_secret
    AUTH_ENCRYPTION_SECRET  = var.mcp_context_forge_auth_encryption_secret
  })

  data_json_wo_version = 5
}

resource "vault_kv_secret_v2" "mcp_database_url" {
  mount = vault_mount.mcp_context_forge.path
  name  = "database-url"

  data_json_wo = jsonencode({
    DATABASE_URL = "postgresql+psycopg://mcpuser:${ephemeral.random_password.mcp_postgres_password.result}@mcp-postgres.ai-system:5432/postgresdb"
  })
  data_json_wo_version = 2
}

########################################################################
# Kubernetes auth role for the mcp-context-forge service account
########################################################################

resource "vault_policy" "mcp_context_forge" {
  name = "mcp-context-forge"

  policy = <<EOT
path "${vault_mount.mcp_context_forge.path}/data/postgres" {
  capabilities = ["read"]
}

path "${vault_mount.mcp_context_forge.path}/data/app" {
  capabilities = ["read"]
}

path "${vault_mount.mcp_context_forge.path}/data/database-url" {
  capabilities = ["read"]
}
EOT
}

resource "vault_kubernetes_auth_backend_role" "mcp_context_forge" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "mcp-context-forge"
  bound_service_account_names      = ["mcp-context-forge"]
  bound_service_account_namespaces = ["ai-system"]
  token_ttl                        = 3600
  token_policies = [
    vault_policy.mcp_context_forge.name,
    vault_policy.token_lookup_renew.name,
  ]
}
