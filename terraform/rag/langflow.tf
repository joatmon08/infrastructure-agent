data "aws_ecr_repository" "langflow" {
  name = "${var.project_name}-langflow"
}

data "aws_ecr_image" "langflow_latest" {
  repository_name = data.aws_ecr_repository.langflow.name
  most_recent     = true
}

resource "random_password" "langflow_superuser" {
  length  = 16
  special = false
}

resource "kubernetes_secret_v1" "langflow_credentials" {
  metadata {
    name      = "langflow-credentials"
    namespace = "default"
  }

  data = {
    superuser-password = random_password.langflow_superuser.result
    secret-key         = var.langflow_secret_key
  }

  type = "Opaque"
}

resource "helm_release" "langflow" {
  name       = "langflow"
  repository = "https://langflow-ai.github.io/langflow-helm-charts"
  chart      = "langflow-ide"

  values = [
    yamlencode({
      securityContext = {
        readOnlyRootFilesystem = false
      }

      langflow = {
        backend = {
          image = {
            repository = data.aws_ecr_repository.langflow.repository_url
            tag        = split(":", data.aws_ecr_image.langflow_latest.image_tags[0])[0]
          }
          sqlite = {
            volume = {
              size = "20Gi"
              storageClass = {
                provisioner = "ebs.csi.aws.com"
              }
            }
          }
          autoLogin       = false
          superuser       = "administrator"
          newUserIsActive = true
          resources = {
            requests = {
              cpu    = "2"
              memory = "6Gi"
            }
          }
          env = [
            {
              name  = "LANGFLOW_WORKER_TIMEOUT"
              value = "3000"
            },
            {
              name = "LANGFLOW_SUPERUSER_PASSWORD"
              valueFrom = {
                secretKeyRef = {
                  name = kubernetes_secret_v1.langflow_credentials.metadata[0].name
                  key  = "superuser-password"
                }
              }
            },
            {
              name = "LANGFLOW_SECRET_KEY"
              valueFrom = {
                secretKeyRef = {
                  name = kubernetes_secret_v1.langflow_credentials.metadata[0].name
                  key  = "secret-key"
                }
              }
            }
          ]
        }

        frontend = {
          resources = {
            requests = {
              cpu    = "2"
              memory = "6Gi"
            }
          }
        }
      }
    })
  ]

  depends_on = [
    data.terraform_remote_state.base,
    kubernetes_secret_v1.langflow_credentials
  ]
}