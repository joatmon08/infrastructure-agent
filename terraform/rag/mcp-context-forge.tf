# Generate secure passwords for MCP Context Forge
resource "random_password" "mcp_admin_password" {
  length  = 16
  special = true
}

resource "random_password" "mcp_jwt_secret" {
  length  = 64
  special = false
}

# MCP Context Forge Deployment using Helm Chart
resource "helm_release" "mcp_context_forge" {
  name      = "mcp-context-forge"
  chart     = "${path.module}/../../charts/mcp-context-forge/charts/mcp-stack"
  namespace = "default"
  timeout   = 600

  # Required secret values
  set_sensitive = [{
    name  = "mcpContextForge.secret.PLATFORM_ADMIN_EMAIL"
    value = var.mcp_admin_email
    }, {
    name  = "mcpContextForge.secret.PLATFORM_ADMIN_PASSWORD"
    value = random_password.mcp_admin_password.result
    }, {
    name  = "mcpContextForge.secret.JWT_SECRET_KEY"
    value = random_password.mcp_jwt_secret.result
  }]

  values = [
    yamlencode({
      mcpContextForge = {
        ingress = {
          enabled   = true
          className = "alb"
          host      = "mcp-context-forge.local"
          path      = "/"
          pathType  = "Prefix"
          annotations = {
            "alb.ingress.kubernetes.io/scheme"                       = "internet-facing"
            "alb.ingress.kubernetes.io/target-type"                  = "ip"
            "alb.ingress.kubernetes.io/inbound-cidrs"                = "${join(",", [for s in var.inbound_cidrs_for_lbs : s])}"
            "alb.ingress.kubernetes.io/load-balancer-attributes"     = "idle_timeout.timeout_seconds=1800"
            "alb.ingress.kubernetes.io/success-codes"                = "200,201,404"
            "alb.ingress.kubernetes.io/tags"                         = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
            "alb.ingress.kubernetes.io/healthcheck-path"             = "/health"
            "alb.ingress.kubernetes.io/healthcheck-interval-seconds" = "30"
            "alb.ingress.kubernetes.io/healthcheck-timeout-seconds"  = "5"
          }
          tls = {
            enabled = false
          }
        }
        metrics = {
          enabled = false
          serviceMonitor = {
            enabled = false
          }
        }
      }
      monitoring = {
        enabled = false
      }
    })
  ]

  depends_on = [
    data.terraform_remote_state.base
  ]
}