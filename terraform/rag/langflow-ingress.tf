resource "kubernetes_ingress_v1" "langflow" {
  metadata {
    name = "langflow"
    annotations = {
      "alb.ingress.kubernetes.io/scheme"                   = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"              = "ip"
      "alb.ingress.kubernetes.io/inbound-cidrs"            = "${join(",", [for s in var.inbound_cidrs_for_lbs : s])}"
      "alb.ingress.kubernetes.io/load-balancer-attributes" = "idle_timeout.timeout_seconds=1800"
      "alb.ingress.kubernetes.io/success-codes"            = "200,201,404"
      "alb.ingress.kubernetes.io/tags"                     = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
    }
    labels = {
      app = "langflow"
    }
  }

  spec {
    ingress_class_name = "alb"

    rule {
      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = "langflow-service"
              port {
                number = 8080
              }
            }
          }
        }

        path {
          path      = "/api"
          path_type = "Prefix"

          backend {
            service {
              name = "langflow-service-backend"
              port {
                number = 7860
              }
            }
          }
        }
      }
    }
  }

  depends_on = [
    helm_release.langflow
  ]
}