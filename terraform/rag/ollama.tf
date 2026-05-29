resource "kubernetes_persistent_volume_claim_v1" "ollama_data" {
  metadata {
    name = "ollama-data"
    labels = {
      app = "ollama"
    }
  }

  spec {
    access_modes = ["ReadWriteOnce"]
    
    resources {
      requests = {
        storage = "30Gi"
      }
    }
    
    storage_class_name = "gp3"
  }
}

resource "kubernetes_service_v1" "ollama" {
  metadata {
    name = "ollama"
    labels = {
      app = "ollama"
    }
  }

  spec {
    type = "ClusterIP"
    
    port {
      port        = 11434
      target_port = 11434
      protocol    = "TCP"
      name        = "http"
    }
    
    selector = {
      app = "ollama"
    }
  }
}

resource "kubernetes_deployment_v1" "ollama" {
  metadata {
    name = "ollama"
    labels = {
      app = "ollama"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "ollama"
      }
    }

    template {
      metadata {
        labels = {
          app = "ollama"
        }
      }

      spec {
        node_selector = {
          "workload-type" = "gpu"
        }

        toleration {
          key      = "nvidia.com/gpu"
          operator = "Equal"
          value    = "true"
          effect   = "NoSchedule"
        }

        container {
          name              = "ollama"
          image             = "ollama/ollama:latest"
          image_pull_policy = "Always"

          port {
            container_port = 11434
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name  = "OLLAMA_CONTEXT_LENGTH"
            value = "131072"
          }

          volume_mount {
            name       = "ollama-data"
            mount_path = "/root/.ollama"
          }

          resources {
            requests = {
              memory = "10Gi"
              cpu    = "4"
            }
            limits = {
              "nvidia.com/gpu" = "1"
            }
          }

          liveness_probe {
            http_get {
              path = "/"
              port = 11434
            }
            initial_delay_seconds = 60
            period_seconds        = 30
          }

          readiness_probe {
            http_get {
              path = "/"
              port = 11434
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
        }

        volume {
          name = "ollama-data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.ollama_data.metadata[0].name
          }
        }
      }
    }
  }
}