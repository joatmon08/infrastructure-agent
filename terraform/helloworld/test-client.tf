# Data source to get the latest test-client ECR image
data "aws_ecr_image" "test_client_latest" {
  repository_name = data.terraform_remote_state.base.outputs.test_client_ecr_repository_name
  most_recent     = true
}

# ConfigMap for test-client
resource "kubernetes_config_map_v1" "test_client" {
  metadata {
    name = local.test_client_name
  }

  data = {
    BASE_URL = data.terraform_remote_state.vault.outputs.test_client_url
  }
}

# Deployment for test-client
resource "kubernetes_deployment_v1" "test_client" {
  metadata {
    name = local.test_client_name
    labels = {
      app = local.test_client_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.test_client_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.test_client_name
        }
        annotations = {
          "vault.hashicorp.com/agent-inject"                              = "true"
          "vault.hashicorp.com/role"                                      = "test-client"
          "vault.hashicorp.com/agent-inject-token"                        = "true"
          "vault.hashicorp.com/agent-run-as-same-user"                    = "true"
          "vault.hashicorp.com/tls-skip-verify"                           = "true"
          "vault.hashicorp.com/agent-inject-secret-client_secrets.json"   = "identity/oidc/client/agent"
          "vault.hashicorp.com/agent-inject-template-client_secrets.json" = <<-EOT
            {
            {{- with secret "identity/oidc/client/agent" }}
                "client_id": "{{ .Data.client_id }}",
                "client_secret": "{{ .Data.client_secret }}",
                "redirect_uris": {{ .Data.redirect_uris | toJSON }}
            {{- end }}
            }
          EOT
          "vault.hashicorp.com/agent-inject-secret-oidc_provider.json"    = "identity/oidc/provider/agent/.well-known/openid-configuration"
          "vault.hashicorp.com/agent-inject-template-oidc_provider.json"  = <<-EOT
            {
            {{- with secret "identity/oidc/provider/agent/.well-known/openid-configuration" }}
                "authorization_endpoint": "{{ .Data.authorization_endpoint }}",
                "issuer": "{{ .Data.issuer }}",
                "token_endpoint": "{{ .Data.token_endpoint }}",
                "userinfo_endpoint": "{{ .Data.userinfo_endpoint }}"
            {{- end }}
            }
          EOT
          "vault.hashicorp.com/agent-inject-secret-actor_token"           = "identity/oidc/token/test-client"
          "vault.hashicorp.com/agent-inject-template-actor_token"         = <<-EOT
            {{- with secret "identity/oidc/token/test-client" -}}
            {{ .Data.token }}
            {{- end }}
          EOT
        }
      }

      spec {
        service_account_name = local.test_client_name

        container {
          name  = local.test_client_name
          image = local.test_client_image

          port {
            container_port = local.test_client_port
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name = "AGENT_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.helloworld_agent_server.metadata[0].name
                key  = "AGENT_URL"
              }
            }
          }

          env {
            name = "BASE_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.test_client.metadata[0].name
                key  = "BASE_URL"
              }
            }
          }

          env {
            name  = "OIDC_PROVIDER_CONFIG_PATH"
            value = "/vault/secrets/oidc_provider.json"
          }

          env {
            name  = "CLIENT_SECRETS_PATH"
            value = "/vault/secrets/client_secrets.json"
          }

          env {
            name  = "ACTOR_TOKEN_PATH"
            value = "/vault/secrets/actor_token"
          }

          env {
            name  = "VAULT_ADDR"
            value = "https://vault-ui.vault"
          }

          env {
            name  = "VAULT_TOKEN_PATH"
            value = "/vault/secrets/token"
          }

          resources {
            requests = {
              memory = "128Mi"
              cpu    = "100m"
            }
            limits = {
              memory = "512Mi"
              cpu    = "500m"
            }
          }

          liveness_probe {
            http_get {
              path = "/"
              port = local.test_client_port
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/"
              port = local.test_client_port
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 1001
            run_as_group               = 1001
            allow_privilege_escalation = false
            read_only_root_filesystem  = false

            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }
}