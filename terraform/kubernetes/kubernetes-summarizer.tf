resource "kubernetes_namespace_v1" "summarizer" {
  metadata {
    name = var.kubernetes_namespace_summarizer
  }
}

resource "kubernetes_ingress_v1" "summarizer_agent" {
  metadata {
    name      = local.summarizer_agent_name
    namespace = kubernetes_namespace_v1.summarizer.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = join(",", var.inbound_cidrs_for_lbs)
      "alb.ingress.kubernetes.io/success-codes"    = "200,201,404"
      "alb.ingress.kubernetes.io/tags"             = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
    }
  }

  spec {
    ingress_class_name = "alb"

    default_backend {
      service {
        name = local.summarizer_agent_name
        port {
          number = local.summarizer_agent_port
        }
      }
    }

    rule {
      http {
        path {
          backend {
            service {
              name = local.summarizer_agent_name
              port {
                number = local.summarizer_agent_port
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
