data "aws_ecr_repository" "langflow" {
  name = "${var.project_name}-langflow"
}

data "aws_ecr_image" "langflow_latest" {
  repository_name = data.aws_ecr_repository.langflow.name
  most_recent     = true
}

resource "random_password" "langflow_superuser" {
  length  = 32
  special = true
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
          autoLogin         = false
          superuser         = "admin"
          superuserPassword = random_password.langflow_superuser.result
          newUserIsActive   = true
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
    data.terraform_remote_state.base
  ]
}