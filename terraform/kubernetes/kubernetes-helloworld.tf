resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "${join(",", [for s in var.inbound_cidrs_for_lbs : s])}"
      "alb.ingress.kubernetes.io/success-codes"    = "200,201,404"
      "alb.ingress.kubernetes.io/tags"             = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
    }
  }

  spec {
    ingress_class_name = "alb"

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

resource "kubernetes_ingress_v1" "test_client" {
  metadata {
    name = local.client_username
    annotations = {
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path" = "/"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = "${join(",", [for s in var.inbound_cidrs_for_lbs : s])}"
      "alb.ingress.kubernetes.io/success-codes"    = "200"
      "alb.ingress.kubernetes.io/tags"             = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
    }
  }

  spec {
    ingress_class_name = "alb"

    default_backend {
      service {
        name = local.client_username
        port {
          number = 80
        }
      }
    }

    rule {
      http {
        path {
          backend {
            service {
              name = local.client_username
              port {
                number = 80
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
