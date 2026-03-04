# Data source to get the latest ECR image
data "aws_ecr_image" "helloworld_agent_latest" {
  repository_name = data.terraform_remote_state.base.outputs.helloworld_agent_ecr_repository_name
  most_recent     = true
}

locals {
  app_image = "${data.terraform_remote_state.base.outputs.helloworld_agent_ecr_repository_url}@${data.aws_ecr_image.helloworld_agent_latest.image_digest}"
}

# ConfigMap for the helloworld agent
resource "kubernetes_config_map_v1" "helloworld_agent_server" {
  metadata {
    name = var.app_name
  }

  data = {
    AGENT_URL          = data.terraform_remote_state.kubernetes.outputs.helloworld_agent_server_url
    OPENID_CONNECT_URL = data.terraform_remote_state.kubernetes.outputs.openid_connect_url
  }
}

# Service for the helloworld agent
resource "kubernetes_service_v1" "helloworld_agent_server" {
  metadata {
    name = var.app_name
    labels = {
      app = var.app_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = var.app_port
      target_port = var.app_port
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = var.app_name
    }
  }
}

# Deployment for the helloworld agent
resource "kubernetes_deployment_v1" "helloworld_agent_server" {
  metadata {
    name = var.app_name
    labels = {
      app = var.app_name
    }
  }

  spec {
    replicas = var.app_replicas

    selector {
      match_labels = {
        app = var.app_name
      }
    }

    template {
      metadata {
        labels = {
          app = var.app_name
        }
      }

      spec {
        container {
          name  = var.app_name
          image = local.app_image

          port {
            container_port = var.app_port
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name  = "VAULT_SKIP_VERIFY"
            value = var.vault_skip_verify
          }

          env {
            name = "AGENT_URL"
            value_from {
              config_map_key_ref {
                name = var.app_name
                key  = "AGENT_URL"
              }
            }
          }

          env {
            name = "OPENID_CONNECT_URL"
            value_from {
              config_map_key_ref {
                name = var.app_name
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
              port = var.app_port
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/.well-known/agent-card.json"
              port = var.app_port
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