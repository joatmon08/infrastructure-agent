# Data source to get the latest test-client ECR image
data "aws_ecr_image" "test_client_latest" {
  repository_name = data.terraform_remote_state.base.outputs.test_client_ecr_repository_name
  most_recent     = true
}

data "kubernetes_ingress_v1" "test_client" {
  metadata {
    name = local.test_client_name
  }
}

# ConfigMap for test-client
resource "kubernetes_config_map_v1" "test_client" {
  metadata {
    name = local.test_client_name
  }

  data = {
    BASE_URL = "http://${data.kubernetes_ingress_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}"
  }
}

resource "kubernetes_service_v1" "test_client" {
  metadata {
    name = local.test_client_name
    labels = {
      app = local.test_client_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 80
      target_port = 9000
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = local.test_client_name
    }
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
          "vault.hashicorp.com/agent-inject"                      = "true"
          "vault.hashicorp.com/role"                              = "test-client"
          "vault.hashicorp.com/agent-inject-secret-vault-token"   = "auth/token/create/test-client"
          "vault.hashicorp.com/agent-inject-template-vault-token" = <<-EOT
            {{- with secret "auth/token/create/test-client" "role_name=test-client" -}}
            {{ .auth.client_token }}
            {{- end }}
          EOT
        }
      }

      spec {
        service_account_name = local.test_client_name

        volume {
          name = "client-secrets"
          secret {
            secret_name = "test-client-secrets"
          }
        }

        volume {
          name = "oidc-provider"
          secret {
            secret_name = "test-client-oidc-provider"
          }
        }

        volume {
          name = "actor-token"
          secret {
            secret_name = "test-client-actor-token"
          }
        }

        container {
          name  = local.test_client_name
          image = local.test_client_image

          port {
            container_port = local.test_client_port
            name           = "http"
            protocol       = "TCP"
          }

          volume_mount {
            name       = "client-secrets"
            mount_path = "/vault/secrets/client"
            read_only  = true
          }

          volume_mount {
            name       = "oidc-provider"
            mount_path = "/vault/secrets/oidc"
            read_only  = true
          }

          volume_mount {
            name       = "actor-token"
            mount_path = "/vault/secrets/actor"
            read_only  = true
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
            value = "/vault/secrets/oidc/oidc_provider.json"
          }

          env {
            name  = "CLIENT_SECRETS_PATH"
            value = "/vault/secrets/client/client_secrets.json"
          }

          env {
            name  = "ACTOR_TOKEN_PATH"
            value = "/vault/secrets/actor/actor_token"
          }

          env {
            name  = "VAULT_ADDR"
            value = data.terraform_remote_state.vault.outputs.vault_private_endpoint
          }

          env {
            name  = "VAULT_TOKEN_PATH"
            value = "/vault/secrets/vault-token"
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

  lifecycle {
    replace_triggered_by = [
      kubernetes_config_map_v1.helloworld_agent_server,
      kubernetes_config_map_v1.test_client
    ]
  }
}