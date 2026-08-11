########################################################################
# Service account for Vault Secrets Operator to sync secrets
########################################################################

resource "kubernetes_service_account_v1" "mcp_context_forge" {
  metadata {
    name      = "mcp-context-forge"
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = "mcp-context-forge"
    }
  }
}

########################################################################
# VaultAuth — Kubernetes auth method for mcp-context-forge SA
########################################################################

resource "kubernetes_manifest" "vault_auth_mcp_context_forge" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "mcp-context-forge"
      namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    }
    spec = {
      method = "kubernetes"
      mount  = "kubernetes"
      kubernetes = {
        role           = "mcp-context-forge"
        serviceAccount = kubernetes_service_account_v1.mcp_context_forge.metadata[0].name
      }
    }
  }

  depends_on = [kubernetes_service_account_v1.mcp_context_forge]
}

########################################################################
# VaultStaticSecret — postgres credentials
########################################################################

resource "kubernetes_manifest" "vault_secret_mcp_postgres" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultStaticSecret"
    metadata = {
      name      = "mcp-postgres"
      namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    }
    spec = {
      type  = "kv-v2"
      mount = "mcp-context-forge"
      path  = "postgres"

      destination = {
        name   = "mcp-postgres"
        create = true
      }

      vaultAuthRef = kubernetes_manifest.vault_auth_mcp_context_forge.manifest.metadata.name
    }
  }

  depends_on = [kubernetes_manifest.vault_auth_mcp_context_forge]
}

########################################################################
# VaultStaticSecret — app credentials (admin password, JWT, encryption)
########################################################################

resource "kubernetes_manifest" "vault_secret_mcp_app" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultStaticSecret"
    metadata = {
      name      = "mcp-context-forge"
      namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    }
    spec = {
      type  = "kv-v2"
      mount = "mcp-context-forge"
      path  = "app"

      destination = {
        name   = "mcp-context-forge"
        create = true
      }

      vaultAuthRef = kubernetes_manifest.vault_auth_mcp_context_forge.manifest.metadata.name
    }
  }

  depends_on = [kubernetes_manifest.vault_auth_mcp_context_forge]
}

########################################################################
# VaultStaticSecret — DATABASE_URL connection string
########################################################################

resource "kubernetes_manifest" "vault_secret_mcp_database_url" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultStaticSecret"
    metadata = {
      name      = "mcp-database-url"
      namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    }
    spec = {
      type  = "kv-v2"
      mount = "mcp-context-forge"
      path  = "database-url"

      destination = {
        name   = "mcp-database-url"
        create = true
      }

      vaultAuthRef = kubernetes_manifest.vault_auth_mcp_context_forge.manifest.metadata.name
    }
  }

  depends_on = [kubernetes_manifest.vault_auth_mcp_context_forge]
}
