resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "100.8.117.17/32"
    }
  }

  spec {
    default_backend {
      service {
        name = local.server_username
        port {
          number = 9999
        }
      }
    }

    rule {
      http {
        path {
          backend {
            service {
              name = local.server_username
              port {
                number = 9999
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }

        path {
          backend {
            service {
              name = "test-client"
              port {
                number = 9000
              }
            }
          }

          path      = "/client"
          path_type = "Prefix"
        }
      }
    }
  }
}

resource "kubernetes_config_map_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
  }

  data = {
    OPENID_CONNECT_URL = "${hcp_vault_cluster.main.vault_public_endpoint_url}/v1/${hcp_vault_cluster.main.namespace}/identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/.well-known/openid-configuration"
    AGENT_URL          = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}/"
  }
}

resource "kubernetes_config_map_v1" "helloworld_agent_client" {
  metadata {
    name = local.client_username
  }

  data = {
    AGENT_URL                    = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}/"
    OPENID_CONNECT_PROVIDER_NAME = vault_identity_oidc_provider.agent.name
    OPENID_CONNECT_CLIENT_NAME   = vault_identity_oidc_client.agent.name
  }
}
