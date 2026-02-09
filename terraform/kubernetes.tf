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
              name = "a2a-inspector"
              port {
                number = 8080
              }
            }
          }

          path      = "/inspector"
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
    OPENID_CONNECT_URL = "${hcp_vault_cluster.main.vault_public_endpoint_url}/v1/identity/oidc/provider/agent/.well-known/openid-configuration"
    USERINFO_ENDPOINT  = data.vault_identity_oidc_openid_config.agent.userinfo_endpoint
    AGENT_URL          = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}/"
  }
}

resource "kubernetes_config_map_v1" "helloworld_agent_client" {
  metadata {
    name = local.client_username
  }

  data = {
    TOKEN_ENDPOINT         = data.vault_identity_oidc_openid_config.agent.token_endpoint
    AUTHORIZATION_ENDPOINT = data.vault_identity_oidc_openid_config.agent.authorization_endpoint
  }
}
