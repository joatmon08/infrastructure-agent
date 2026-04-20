# # Data source to get the latest ECR image
# data "aws_ecr_image" "helloworld_agent_latest" {
#   repository_name = data.terraform_remote_state.base.outputs.helloworld_agent_ecr_repository_name
#   most_recent     = true
# }

# ConfigMap for the helloworld agent
resource "kubernetes_config_map_v1" "helloworld_agent_server" {
  metadata {
    name = local.helloworld_agent_name
  }

  data = {
    AGENT_URL          = data.terraform_remote_state.vault.outputs.helloworld_agent_server_url
    OPENID_CONNECT_URL = data.terraform_remote_state.vault.outputs.openid_connect_url
  }
}

# # Service for the helloworld agent
# resource "kubernetes_service_v1" "helloworld_agent_server" {
#   metadata {
#     name = local.helloworld_agent_name
#     labels = {
#       app = local.helloworld_agent_name
#     }
#   }

#   spec {
#     type = "ClusterIP"

#     port {
#       port        = local.helloworld_agent_port
#       target_port = local.helloworld_agent_port
#       protocol    = "TCP"
#       name        = "http"
#     }

#     selector = {
#       app = local.helloworld_agent_name
#     }
#   }
# }

# # Deployment for the helloworld agent
# resource "kubernetes_deployment_v1" "helloworld_agent_server" {
#   metadata {
#     name = local.helloworld_agent_name
#     labels = {
#       app = local.helloworld_agent_name
#     }
#   }

#   spec {
#     replicas = var.app_replicas

#     selector {
#       match_labels = {
#         app = local.helloworld_agent_name
#       }
#     }

#     template {
#       metadata {
#         labels = {
#           app = local.helloworld_agent_name
#         }
#       }

#       spec {
#         container {
#           name  = local.helloworld_agent_name
#           image = local.helloworld_agent_image

#           port {
#             container_port = local.helloworld_agent_port
#             name           = "http"
#             protocol       = "TCP"
#           }

#           env {
#             name  = "VAULT_SKIP_VERIFY"
#             value = var.vault_skip_verify
#           }

#           env {
#             name = "AGENT_URL"
#             value_from {
#               config_map_key_ref {
#                 name = kubernetes_config_map_v1.helloworld_agent_server.metadata[0].name
#                 key  = "AGENT_URL"
#               }
#             }
#           }

#           env {
#             name = "OPENID_CONNECT_URL"
#             value_from {
#               config_map_key_ref {
#                 name = kubernetes_config_map_v1.helloworld_agent_server.metadata[0].name
#                 key  = "OPENID_CONNECT_URL"
#               }
#             }
#           }

#           resources {
#             requests = {
#               memory = var.memory_request
#               cpu    = var.cpu_request
#             }
#             limits = {
#               memory = var.memory_limit
#               cpu    = var.cpu_limit
#             }
#           }

#           liveness_probe {
#             http_get {
#               path = "/.well-known/agent-card.json"
#               port = local.helloworld_agent_port
#             }
#             initial_delay_seconds = 30
#             period_seconds        = 10
#           }

#           readiness_probe {
#             http_get {
#               path = "/.well-known/agent-card.json"
#               port = local.helloworld_agent_port
#             }
#             initial_delay_seconds = 5
#             period_seconds        = 5
#           }

#           security_context {
#             run_as_non_root            = true
#             run_as_user                = 1001
#             run_as_group               = 1001
#             allow_privilege_escalation = false
#             read_only_root_filesystem  = false

#             capabilities {
#               drop = ["ALL"]
#             }
#           }
#         }
#       }
#     }
#   }
# }

