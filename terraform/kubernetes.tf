resource "kubernetes_storage_class_v1" "auto_mode" {
  metadata {
    name = "auto-ebs-sc"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  storage_provisioner = "ebs.csi.eks.amazonaws.com"
  reclaim_policy      = "Delete"
  volume_binding_mode = "WaitForFirstConsumer"
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }
}

resource "kubernetes_manifest" "ingressclassparams_alb" {
  manifest = {
    "apiVersion" = "eks.amazonaws.com/v1"
    "kind"       = "IngressClassParams"
    "metadata" = {
      "name" = "alb"
    }
    "spec" = {
      "scheme" = "internet-facing"
    }
  }
}

resource "kubernetes_ingress_class_v1" "alb" {
  metadata {
    name = "alb"
    annotations = {
      "ingressclass.kubernetes.io/is-default-class" = "true"
    }
  }

  spec {
    controller = "eks.amazonaws.com/alb"
    parameters {
      api_group = "eks.amazonaws.com"
      kind      = "IngressClassParams"
      name      = "alb"
    }
  }
}

resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "${join(",", [for s in var.inbound_cidrs_for_lbs : format("%q", s)])}"
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
    AGENT_URL                    = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}"
    OPENID_CONNECT_PROVIDER_NAME = vault_identity_oidc_provider.agent.name
    OPENID_CONNECT_CLIENT_NAME   = vault_identity_oidc_client.agent.name
    VAULT_ADDR                   = hcp_vault_cluster.main.vault_public_endpoint_url
    VAULT_NAMESPACE              = hcp_vault_cluster.main.namespace
  }
}
