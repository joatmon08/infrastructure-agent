resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "${join(",", [for s in var.inbound_cidrs_for_lbs : s])}"
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

resource "kubernetes_service_v1" "test_client" {
  metadata {
    name = local.client_username
    labels = {
      app = local.client_username
    }
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-type"      = "nlb"
      "service.beta.kubernetes.io/load-balancer-source-ranges" = join(",", var.inbound_cidrs_for_lbs)
      "service.beta.kubernetes.io/aws-load-balancer-scheme"    = "internet-facing"
    }
  }

  spec {
    type = "LoadBalancer"

    port {
      port        = 80
      target_port = 9000
      protocol    = "TCP"
      name        = "http"
    }

    load_balancer_class = "eks.amazonaws.com/nlb"

    selector = {
      app = local.client_username
    }
  }
}