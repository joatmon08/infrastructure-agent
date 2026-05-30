resource "random_password" "opensearch_admin" {
  length  = 16
  special = false
}

resource "kubernetes_secret_v1" "opensearch_admin" {
  metadata {
    name = "opensearch-admin"
    labels = {
      app = "opensearch"
    }
  }

  data = {
    password = random_password.opensearch_admin.result
  }

  type = "Opaque"
}

resource "helm_release" "opensearch" {
  name       = "opensearch"
  repository = "https://opensearch-project.github.io/helm-charts/"
  chart      = "opensearch"

  values = [
    yamlencode({
      config = {
        "opensearch.yml" = <<-EOT
          cluster.name: opensearch-cluster
          network.host: 0.0.0.0
        EOT
      }

      # Security configuration
      extraEnvs = [
        {
          name = "OPENSEARCH_INITIAL_ADMIN_PASSWORD"
          valueFrom = {
            secretKeyRef = {
              name = kubernetes_secret_v1.opensearch_admin.metadata[0].name
              key  = "password"
            }
          }
        }
      ]

      # Resource configuration
      resources = {
        requests = {
          cpu    = "1"
          memory = "2Gi"
        }
      }

      # Persistence configuration
      persistence = {
        enabled      = true
        size         = "30Gi"
        storageClass = "gp3"
      }

      # Single node cluster for development
      replicas = 1

      # Security context - non-root user
      securityContext = {
        runAsUser  = 1000
        runAsGroup = 1000
        fsGroup    = 1000
      }
    })
  ]

  depends_on = [
    data.terraform_remote_state.base,
    kubernetes_secret_v1.opensearch_admin
  ]
}

resource "kubernetes_service_v1" "opensearch" {
  metadata {
    name = "opensearch"
    labels = {
      app = "opensearch"
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 9200
      target_port = 9200
      protocol    = "TCP"
      name        = "http"
    }

    port {
      port        = 9300
      target_port = 9300
      protocol    = "TCP"
      name        = "transport"
    }

    selector = {
      app = "opensearch"
    }
  }

  depends_on = [
    helm_release.opensearch
  ]
}