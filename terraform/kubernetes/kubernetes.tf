locals {
  inbound_cidrs_for_agent_server = concat(var.inbound_cidrs_for_lbs, [data.terraform_remote_state.base.outputs.vpc_cidr_block])
}
resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "${join(",", [for s in local.inbound_cidrs_for_agent_server : s])}"
      "alb.ingress.kubernetes.io/success-codes"    = "200,201,404"
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
      }
    }
  }
  depends_on = [kubernetes_ingress_class_v1.alb, kubernetes_manifest.ingressclassparams_alb]
}

resource "kubernetes_config_map_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
  }

  data = {
    OPENID_CONNECT_URL = "${data.terraform_remote_state.base.outputs.vault_endpoint}/v1/identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/.well-known/openid-configuration"
    AGENT_URL          = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}"
  }
}