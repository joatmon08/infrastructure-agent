# Data source to get the latest ECR image
data "aws_ecr_image" "helloworld_agent_latest" {
  repository_name = data.terraform_remote_state.base.outputs.helloworld_agent_ecr_repository_name
  most_recent     = true
}

data "kubernetes_ingress_v1" "helloworld_server" {
  metadata {
    name = local.helloworld_agent_name
  }
}

# ConfigMap for the helloworld agent
resource "kubernetes_config_map_v1" "helloworld_agent_server" {
  metadata {
    name = local.helloworld_agent_name
  }

  data = {
    AGENT_URL          = "http://${data.kubernetes_ingress_v1.helloworld_server.status.0.load_balancer.0.ingress.0.hostname}"
    OPENID_CONNECT_URL = data.terraform_remote_state.vault.outputs.token_exchange_openid_configuration_endpoint
  }
}

# Service for the helloworld agent
resource "kubernetes_service_v1" "helloworld_agent_server" {
  metadata {
    name = local.helloworld_agent_name
    labels = {
      app = local.helloworld_agent_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = local.helloworld_agent_port
      target_port = local.helloworld_agent_port
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = local.helloworld_agent_name
    }
  }
}

# Deployment for the helloworld agent
resource "kubernetes_deployment_v1" "helloworld_agent_server" {
  metadata {
    name = local.helloworld_agent_name
    labels = {
      app = local.helloworld_agent_name
    }
  }

  spec {
    replicas = var.app_replicas

    selector {
      match_labels = {
        app = local.helloworld_agent_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.helloworld_agent_name
        }
      }

      spec {
        container {
          name  = local.helloworld_agent_name
          image = local.helloworld_agent_image

          port {
            container_port = local.helloworld_agent_port
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name  = "TLS_VERIFY"
            value = var.verify_openid_config_tls
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
            name = "OPENID_CONNECT_URL"
            value_from {
              config_map_key_ref {
                name = kubernetes_config_map_v1.helloworld_agent_server.metadata[0].name
                key  = "OPENID_CONNECT_URL"
              }
            }
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
              port = local.helloworld_agent_port
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/.well-known/agent-card.json"
              port = local.helloworld_agent_port
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
    replace_triggered_by = [kubernetes_config_map_v1.helloworld_agent_server]
  }
}

