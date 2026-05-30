# Job to initialize OpenSearch index with KNN settings
resource "kubernetes_job_v1" "opensearch_init" {
  metadata {
    name = "opensearch-init"
    labels = {
      app = "opensearch-init"
    }
  }

  spec {
    template {
      metadata {
        labels = {
          app = "opensearch-init"
        }
      }

      spec {
        restart_policy = "OnFailure"

        container {
          name  = "init"
          image = "curlimages/curl:latest"

          command = [
            "/bin/sh",
            "-c",
            <<-EOT
              # Wait for OpenSearch to be ready
              until curl -k -u "admin:$OPENSEARCH_ADMIN_PASSWORD" "https://opensearch-cluster-master:9200/_cluster/health" 2>/dev/null | grep -q '"status":"green"\|"status":"yellow"'; do
                echo "Waiting for OpenSearch to be ready..."
                sleep 5
              done

              # Create the langflow index with KNN settings
              curl -X PUT -k -u "admin:$OPENSEARCH_ADMIN_PASSWORD" \
                "https://opensearch-cluster-master:9200/langflow" \
                -H 'Content-Type: application/json' \
                -d '{
                  "settings": {
                    "index": {
                      "knn": true,
                      "knn.algo_param.ef_search": 512
                    }
                  },
                  "mappings": {
                    "properties": {
                      "chunk_embedding": {
                        "type": "knn_vector",
                        "dimension": 384
                      }
                    }
                  }
                }'

              echo "OpenSearch index initialized successfully"
            EOT
          ]

          env {
            name = "OPENSEARCH_ADMIN_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.opensearch_admin.metadata[0].name
                key  = "password"
              }
            }
          }

          security_context {
            run_as_user  = 1000
            run_as_group = 1000
          }
        }
      }
    }

    backoff_limit = 3
  }

  wait_for_completion = true

  timeouts {
    create = "5m"
    update = "5m"
  }

  depends_on = [
    helm_release.opensearch,
    kubernetes_secret_v1.opensearch_admin
  ]
}