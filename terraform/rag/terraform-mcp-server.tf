# Terraform MCP Server Secret
resource "kubernetes_secret_v1" "terraform_mcp_server" {
  metadata {
    name = "terraform-mcp-server-secret"
  }

  data = {
    tfe-token = var.tfe_token
  }

  type = "Opaque"
}

# Terraform MCP Server Service
resource "kubernetes_service_v1" "terraform_mcp_server" {
  metadata {
    name = "terraform-mcp-server"
    labels = {
      app = "terraform-mcp-server"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = "terraform-mcp-server"
    }
  }
}

# Terraform MCP Server Deployment
resource "kubernetes_deployment_v1" "terraform_mcp_server" {
  metadata {
    name = "terraform-mcp-server"
    labels = {
      app = "terraform-mcp-server"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "terraform-mcp-server"
      }
    }

    template {
      metadata {
        labels = {
          app = "terraform-mcp-server"
        }
      }

      spec {
        container {
          name  = "terraform-mcp-server"
          image = "hashicorp/terraform-mcp-server:0.5.2"

          port {
            container_port = 8080
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name  = "TRANSPORT_MODE"
            value = "streamable-http"
          }

          env {
            name  = "TRANSPORT_HOST"
            value = "0.0.0.0"
          }

          env {
            name = "TFE_TOKEN"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.terraform_mcp_server.metadata[0].name
                key  = "tfe-token"
              }
            }
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
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
        }
      }
    }
  }
}

# Made with Bob