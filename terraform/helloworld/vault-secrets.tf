# VaultAuth for test-client using existing service account
resource "kubernetes_manifest" "vault_auth_test_client" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "test-client-auth"
      namespace = "default"
    }
    spec = {
      method = "kubernetes"
      mount  = "kubernetes"
      kubernetes = {
        role           = "test-client"
        serviceAccount = local.test_client_name
      }
    }
  }
}

# VaultDynamicSecret for client_secrets.json (OIDC client credentials)
resource "kubernetes_manifest" "vault_secret_client_secrets" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "test-client-secrets"
      namespace = "default"
    }
    spec = {
      mount = "identity"
      path  = "oidc/client/agent"

      destination = {
        name   = "test-client-secrets"
        create = true
        transformation = {
          templates = {
            "client_secrets.json" = {
              text = <<-EOT
                {
                {{- with .Secrets.client_id }}
                    "client_id": "{{ . }}",
                {{- end }}
                {{- with .Secrets.client_secret }}
                    "client_secret": "{{ . }}",
                {{- end }}
                {{- with .Secrets.redirect_uris }}
                    "redirect_uris": {{ . | toJson }}
                {{- end }}
                }
              EOT
            }
          }
        }
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = local.test_client_name
        }
      ]

      vaultAuthRef = kubernetes_manifest.vault_auth_test_client.manifest.metadata.name
    }
  }

  depends_on = [
    kubernetes_manifest.vault_auth_test_client
  ]
}

# VaultDynamicSecret for oidc_provider.json (OIDC provider configuration)
resource "kubernetes_manifest" "vault_secret_oidc_provider" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "test-client-oidc-provider"
      namespace = "default"
    }
    spec = {
      mount = "identity"
      path  = "oidc/provider/agent/.well-known/openid-configuration"

      destination = {
        name   = "test-client-oidc-provider"
        create = true
        transformation = {
          templates = {
            "oidc_provider.json" = {
              text = <<-EOT
                {
                {{- with .Secrets.authorization_endpoint }}
                    "authorization_endpoint": "{{ . }}",
                {{- end }}
                {{- with .Secrets.issuer }}
                    "issuer": "{{ . }}",
                {{- end }}
                {{- with .Secrets.token_endpoint }}
                    "token_endpoint": "{{ . }}",
                {{- end }}
                {{- with .Secrets.userinfo_endpoint }}
                    "userinfo_endpoint": "{{ . }}"
                {{- end }}
                }
              EOT
            }
          }
        }
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = local.test_client_name
        }
      ]

      vaultAuthRef = kubernetes_manifest.vault_auth_test_client.manifest.metadata.name
    }
  }

  depends_on = [
    kubernetes_manifest.vault_auth_test_client
  ]
}

# VaultDynamicSecret for actor_token (OIDC token for test-client)
resource "kubernetes_manifest" "vault_secret_actor_token" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "test-client-actor-token"
      namespace = "default"
    }
    spec = {
      mount = "identity"
      path  = "oidc/token/test-client"

      destination = {
        name   = "test-client-actor-token"
        create = true
        transformation = {
          templates = {
            "actor_token" = {
              text = <<-EOT
                {{- with .Secrets.token -}}
                {{ . }}
                {{- end }}
              EOT
            }
          }
        }
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = local.test_client_name
        }
      ]

      vaultAuthRef = kubernetes_manifest.vault_auth_test_client.manifest.metadata.name
    }
  }

  depends_on = [
    kubernetes_manifest.vault_auth_test_client
  ]
}

resource "kubernetes_manifest" "vault_secret_token" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "test-client-vault-token"
      namespace = "default"
    }
    spec = {
      mount = "auth"
      path  = "token/create/test-client"

      requestHTTPMethod = "POST"

      destination = {
        name   = "test-client-vault-token"
        create = true
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = local.test_client_name
        }
      ]

      vaultAuthRef = kubernetes_manifest.vault_auth_test_client.manifest.metadata.name
    }
  }

  depends_on = [
    kubernetes_manifest.vault_auth_test_client
  ]
}
