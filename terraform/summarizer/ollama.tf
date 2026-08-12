########################################################################
# Ollama — LLM inference server for GPU workloads
# Deployed in the "ollama" namespace alongside the summarizer-agent.
# Reachable at http://ollama.ollama.svc.cluster.local:11434
########################################################################

resource "kubernetes_namespace_v1" "ollama" {
  metadata {
    name = "ollama"
    labels = {
      app = "ollama"
    }
  }
}

resource "kubernetes_persistent_volume_claim_v1" "ollama_models" {
  metadata {
    name      = "ollama-models"
    namespace = kubernetes_namespace_v1.ollama.metadata[0].name
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "gp3"

    resources {
      requests = {
        storage = "30Gi"
      }
    }
  }
}

resource "kubernetes_deployment_v1" "ollama" {
  metadata {
    name      = "ollama"
    namespace = kubernetes_namespace_v1.ollama.metadata[0].name
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
          "node.kubernetes.io/gpu" = "true"
        }

        toleration {
          key      = "nvidia.com/gpu"
          value    = "true"
          effect   = "NoSchedule"
          operator = "Equal"
        }

        volume {
          name = "ollama-models"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.ollama_models.metadata[0].name
          }
        }

        container {
          name  = "ollama"
          image = "ollama/ollama:latest"

          port {
            container_port = 11434
            name           = "http"
            protocol       = "TCP"
          }

          env {
            name  = "OLLAMA_MODELS"
            value = "/root/.ollama"
          }

          volume_mount {
            name       = "ollama-models"
            mount_path = "/root/.ollama"
          }

          resources {
            requests = {
              memory           = "4Gi"
              cpu              = "1"
              "nvidia.com/gpu" = "1"
            }
            limits = {
              memory           = "12Gi"
              "nvidia.com/gpu" = "1"
            }
          }

          liveness_probe {
            http_get {
              path = "/api/tags"
              port = 11434
            }
            initial_delay_seconds = 60
            period_seconds        = 30
            timeout_seconds       = 10
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/api/tags"
              port = 11434
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          security_context {
            run_as_non_root            = false
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "ollama" {
  metadata {
    name      = "ollama"
    namespace = kubernetes_namespace_v1.ollama.metadata[0].name
    labels = {
      app = "ollama"
    }
  }

  spec {
    type = "ClusterIP"

    selector = {
      app = "ollama"
    }

    port {
      name        = "http"
      port        = 11434
      target_port = 11434
      protocol    = "TCP"
    }
  }
}
