resource "kubernetes_manifest" "vault_auth_summarizer" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "summarizer-auth"
      namespace = local.summarizer_namespace
    }
    spec = {
      method = "kubernetes"
      mount  = "kubernetes"
      kubernetes = {
        role           = local.summarizer_client
        serviceAccount = local.summarizer_client
      }
    }
  }
}

resource "kubernetes_manifest" "vault_secret_actor_token" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "summarizer-actor-token"
      namespace = local.summarizer_namespace
    }
    spec = {
      mount = "identity"
      path  = "oidc/token/${local.summarizer_client}"

      destination = {
        name   = "summarizer-actor-token"
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
          name = local.summarizer_agent_name
        }
      ]

      vaultAuthRef = kubernetes_manifest.vault_auth_summarizer.manifest.metadata.name
    }
  }

  depends_on = [
    kubernetes_manifest.vault_auth_summarizer
  ]
}
