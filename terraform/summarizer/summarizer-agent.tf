data "kubernetes_namespace_v1" "summarizer" {
  metadata {
    name = data.terraform_remote_state.kubernetes.outputs.summarizer_namespace
  }
}

data "kubernetes_service_account_v1" "summarizer_client" {
  metadata {
    name      = local.summarizer_client
    namespace = data.kubernetes_namespace_v1.summarizer.metadata[0].name
  }
}

resource "kubernetes_config_map_v1" "summarizer_agent" {
  metadata {
    name      = local.summarizer_agent_name
    namespace = data.kubernetes_namespace_v1.summarizer.metadata[0].name
  }

  data = {
    AGENT_URL          = data.terraform_remote_state.kubernetes.outputs.summarizer_agent_url
    OPENID_CONNECT_URL = data.terraform_remote_state.vault.outputs.token_exchange_openid_configuration_endpoint
    OLLAMA_URL         = "http://ollama.ollama.svc.cluster.local:11434"
    OLLAMA_MODEL       = var.ollama_model
  }
}

resource "kubernetes_service_v1" "summarizer_agent" {
  metadata {
    name      = local.summarizer_agent_name
    namespace = data.kubernetes_namespace_v1.summarizer.metadata[0].name
    labels = {
      app = local.summarizer_agent_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = local.summarizer_agent_port
      target_port = local.summarizer_agent_port
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = local.summarizer_agent_name
    }
  }
}

resource "kubernetes_deployment_v1" "summarizer_agent" {
  metadata {
    name      = local.summarizer_agent_name
    namespace = data.kubernetes_namespace_v1.summarizer.metadata[0].name
    labels = {
      app = local.summarizer_agent_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.summarizer_agent_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.summarizer_agent_name
        }
      }

      spec {
        service_account_name = data.kubernetes_service_account_v1.summarizer_client.metadata[0].name

        volume {
          name = "actor-token"
          secret {
            secret_name = "summarizer-actor-token"
          }
        }

        container {
          name  = local.summarizer_agent_name
          image = var.summarizer_agent_image

          port {
            container_port = local.summarizer_agent_port
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name = "AGENT_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.summarizer_agent.metadata[0].name
                key  = "AGENT_URL"
              }
            }
          }

          env {
            name = "OPENID_CONNECT_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.summarizer_agent.metadata[0].name
                key  = "OPENID_CONNECT_URL"
              }
            }
          }

          env {
            name = "OLLAMA_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.summarizer_agent.metadata[0].name
                key  = "OLLAMA_URL"
              }
            }
          }

          env {
            name = "OLLAMA_MODEL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.summarizer_agent.metadata[0].name
                key  = "OLLAMA_MODEL"
              }
            }
          }

          env {
            name  = "VERIFY_TLS"
            value = var.verify_openid_config_tls
          }

          env {
            name  = "AGENT_HOST"
            value = "0.0.0.0"
          }

          env {
            name  = "AUTH_ENABLED"
            value = tostring(var.summarizer_agent_auth_enabled)
          }

          resources {
            requests = {
              memory = var.memory_request
              cpu    = var.cpu_request
            }
            limits = {
              memory = var.memory_limit
              cpu    = var.cpu_limit
            }
          }

          liveness_probe {
            http_get {
              path = "/.well-known/agent-card.json"
              port = local.summarizer_agent_port
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/.well-known/agent-card.json"
              port = local.summarizer_agent_port
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
    replace_triggered_by = [kubernetes_config_map_v1.summarizer_agent]
  }
}
