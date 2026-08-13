resource "kubernetes_namespace_v1" "summarizer" {
  metadata {
    name = var.kubernetes_namespace_summarizer
  }
}

data "aws_ip_ranges" "lbs" {
  regions  = [var.aws_region]
  services = ["ec2"]
}

resource "kubernetes_ingress_v1" "summarizer_agent" {
  metadata {
    name      = local.summarizer_agent_name
    namespace = kubernetes_namespace_v1.summarizer.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/scheme"           = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"      = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path" = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"    = join(",", [for s in var.inbound_cidrs_for_lbs : s], [data.terraform_remote_state.base.outputs.vpc_cidr_block], data.aws_ip_ranges.lbs.cidr_blocks)
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
