# Vault Plugin Loader Resources
# This creates a Kubernetes Job to download and deploy custom Vault plugins to EFS

# Variables for plugin configuration
variable "vault_plugins" {
  description = "List of Vault plugins to download and install"
  type = list(object({
    name   = string
    url    = string
    sha256 = string
  }))
  default = []
  # Example:
  # default = [
  #   {
  #     name   = "vault-plugin-secrets-custom"
  #     url    = "https://github.com/org/repo/releases/download/v1.0.0/vault-plugin-secrets-custom"
  #     sha256 = "abc123..."
  #   }
  # ]
}

# ConfigMap containing the plugin loader script
resource "kubernetes_config_map_v1" "vault_plugin_loader_script" {
  metadata {
    name      = "vault-plugin-loader-script"
    namespace = var.kubernetes_namespace_vault
    labels = {
      app       = "vault"
      component = "plugin-loader"
    }
  }

  data = {
    "load-plugins.sh" = templatefile("${path.module}/templates/vault-plugin-loader.sh.tpl", {
      PLUGINS = var.vault_plugins
    })
  }

  depends_on = [
    helm_release.vault
  ]
}

# Job to load plugins into EFS
resource "kubernetes_job_v1" "vault_plugin_loader" {
  count = length(var.vault_plugins) > 0 ? 1 : 0

  metadata {
    name      = "vault-plugin-loader-${formatdate("YYYYMMDDhhmmss", timestamp())}"
    namespace = var.kubernetes_namespace_vault
    labels = {
      app       = "vault"
      component = "plugin-loader"
    }
  }

  spec {
    ttl_seconds_after_finished = 300
    
    template {
      metadata {
        labels = {
          app       = "vault"
          component = "plugin-loader"
        }
      }

      spec {
        restart_policy       = "OnFailure"
        service_account_name = "vault"

        container {
          name  = "plugin-loader"
          # Use official Vault image which includes curl and is maintained by HashiCorp
          image = "hashicorp/vault:${var.vault_helm_chart_version}"
          
          command = ["/bin/sh", "/scripts/load-plugins.sh"]

          volume_mount {
            name       = "plugins"
            mount_path = "/vault/plugins"
          }

          volume_mount {
            name       = "scripts"
            mount_path = "/scripts"
            read_only  = true
          }

          resources {
            requests = {
              memory = "128Mi"
              cpu    = "100m"
            }
            limits = {
              memory = "256Mi"
              cpu    = "200m"
            }
          }

          security_context {
            run_as_non_root = true
            run_as_user     = 100
            run_as_group    = 1000
            capabilities {
              drop = ["ALL"]
            }
            read_only_root_filesystem = false
          }
        }

        volume {
          name = "plugins"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.vault_plugins.metadata[0].name
          }
        }

        volume {
          name = "scripts"
          config_map {
            name         = kubernetes_config_map_v1.vault_plugin_loader_script.metadata[0].name
            default_mode = "0755"
          }
        }

        security_context {
          fs_group = 1000
        }
      }
    }
  }

  wait_for_completion = true
  timeouts {
    create = "5m"
    update = "5m"
  }

  depends_on = [
    kubernetes_config_map_v1.vault_plugin_loader_script,
    kubernetes_persistent_volume_claim_v1.vault_plugins
  ]

  lifecycle {
    replace_triggered_by = [
      kubernetes_config_map_v1.vault_plugin_loader_script
    ]
  }
}

# Output job status
output "vault_plugin_loader_job_name" {
  description = "Name of the plugin loader job"
  value       = length(var.vault_plugins) > 0 ? kubernetes_job_v1.vault_plugin_loader[0].metadata[0].name : "no-plugins-configured"
}