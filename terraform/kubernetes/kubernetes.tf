locals {
  inbound_cidrs_for_agent_server = concat(var.inbound_cidrs_for_lbs, [data.terraform_remote_state.base.outputs.vpc_cidr_block])
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.project_name}-${var.environment}-access-logs"
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${var.project_name}-${var.environment}-access-logs/alb/${local.server_username}/*"
    }
  ]
}
POLICY
}

resource "kubernetes_ingress_v1" "helloworld_agent_server" {
  metadata {
    name = local.server_username
    annotations = {
      "alb.ingress.kubernetes.io/healthcheck-path"         = "/.well-known/agent-card.json"
      "alb.ingress.kubernetes.io/inbound-cidrs"            = "${join(",", [for s in local.inbound_cidrs_for_agent_server : s])}"
      "alb.ingress.kubernetes.io/success-codes"            = "200,201,404"
      "alb.ingress.kubernetes.io/load-balancer-attributes" = "access_logs.s3.enabled=true,access_logs.s3.bucket=${aws_s3_bucket.access_logs.bucket},access_logs.s3.prefix=alb/${local.server_username}"
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