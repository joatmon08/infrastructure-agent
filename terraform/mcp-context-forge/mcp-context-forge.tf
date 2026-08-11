########################################################################
# Namespace
########################################################################

resource "kubernetes_namespace_v1" "ai_system" {
  metadata {
    name = var.kubernetes_namespace
  }
}

########################################################################
# ConfigMap — non-sensitive admin identity variables
########################################################################

resource "kubernetes_config_map_v1" "identity" {
  metadata {
    name      = "${local.mcp_context_forge_app_name}-identity"
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
  }

  data = {
    PLATFORM_ADMIN_EMAIL     = var.mcp_admin_email
    PLATFORM_ADMIN_FULL_NAME = "Platform Administrator"
  }
}

########################################################################
# ConfigMap — non-sensitive application environment variables
########################################################################

resource "kubernetes_config_map_v1" "app" {
  metadata {
    name      = local.mcp_context_forge_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
  }

  data = {
    # ── Gunicorn ──────────────────────────────────────────────────────
    GUNICORN_WORKERS             = "2"
    GUNICORN_TIMEOUT             = "600"
    GUNICORN_MAX_REQUESTS        = "100000"
    GUNICORN_MAX_REQUESTS_JITTER = "100"
    GUNICORN_PRELOAD_APP         = "true"
    GUNICORN_DEV_MODE            = "false"
    DISABLE_ACCESS_LOG           = "true"

    # ── Application ───────────────────────────────────────────────────
    APP_NAME      = "ContextForge"
    HOST          = "0.0.0.0"
    PORT          = "4444"
    APP_ROOT_PATH = ""
    CLIENT_MODE   = "false"

    # ── Database connection pool ──────────────────────────────────────
    DB_POOL_SIZE    = "15"
    DB_MAX_OVERFLOW = "30"
    DB_POOL_TIMEOUT = "30"
    DB_POOL_RECYCLE = "3600"

    # ── Cache ─────────────────────────────────────────────────────────
    CACHE_TYPE   = "redis"
    CACHE_PREFIX = "mcpgw:"
    SESSION_TTL  = "3600"
    MESSAGE_TTL  = "600"

    # ── Redis connection ──────────────────────────────────────────────
    REDIS_MAX_RETRIES               = "30"
    REDIS_RETRY_INTERVAL_MS         = "2000"
    REDIS_MAX_BACKOFF_SECONDS       = "30"
    DB_MAX_RETRIES                  = "30"
    DB_RETRY_INTERVAL_MS            = "2000"
    DB_MAX_BACKOFF_SECONDS          = "30"
    REDIS_MAX_CONNECTIONS           = "50"
    REDIS_SOCKET_TIMEOUT            = "2.0"
    REDIS_SOCKET_CONNECT_TIMEOUT    = "2.0"
    REDIS_RETRY_ON_TIMEOUT          = "true"
    REDIS_HEALTH_CHECK_INTERVAL     = "30"
    REDIS_DECODE_RESPONSES          = "true"
    REDIS_LEADER_TTL                = "15"
    REDIS_LEADER_KEY                = "gateway_service_leader"
    REDIS_LEADER_HEARTBEAT_INTERVAL = "5"

    # ── Auth cache ────────────────────────────────────────────────────
    AUTH_CACHE_ENABLED        = "true"
    AUTH_CACHE_USER_TTL       = "60"
    AUTH_CACHE_REVOCATION_TTL = "30"
    AUTH_CACHE_TEAM_TTL       = "60"
    AUTH_CACHE_ROLE_TTL       = "60"
    AUTH_CACHE_TEAMS_ENABLED  = "true"
    AUTH_CACHE_TEAMS_TTL      = "60"
    AUTH_CACHE_BATCH_QUERIES  = "true"

    # ── Registry cache ────────────────────────────────────────────────
    REGISTRY_CACHE_ENABLED       = "true"
    REGISTRY_CACHE_TOOLS_TTL     = "20"
    REGISTRY_CACHE_PROMPTS_TTL   = "15"
    REGISTRY_CACHE_RESOURCES_TTL = "15"
    REGISTRY_CACHE_AGENTS_TTL    = "20"
    REGISTRY_CACHE_SERVERS_TTL   = "20"
    REGISTRY_CACHE_GATEWAYS_TTL  = "20"
    REGISTRY_CACHE_CATALOG_TTL   = "300"

    # ── Tool lookup cache ─────────────────────────────────────────────
    TOOL_LOOKUP_CACHE_ENABLED              = "true"
    TOOL_LOOKUP_CACHE_TTL_SECONDS          = "60"
    TOOL_LOOKUP_CACHE_NEGATIVE_TTL_SECONDS = "10"
    TOOL_LOOKUP_CACHE_L1_MAXSIZE           = "10000"
    TOOL_LOOKUP_CACHE_L2_ENABLED           = "true"

    # ── Admin stats cache ─────────────────────────────────────────────
    ADMIN_STATS_CACHE_ENABLED           = "true"
    ADMIN_STATS_CACHE_SYSTEM_TTL        = "60"
    ADMIN_STATS_CACHE_OBSERVABILITY_TTL = "30"
    ADMIN_STATS_CACHE_TAGS_TTL          = "120"
    ADMIN_STATS_CACHE_PLUGINS_TTL       = "120"
    ADMIN_STATS_CACHE_PERFORMANCE_TTL   = "60"
    TEAM_MEMBER_COUNT_CACHE_ENABLED     = "true"
    TEAM_MEMBER_COUNT_CACHE_TTL         = "300"
    METRICS_CACHE_ENABLED               = "true"
    METRICS_CACHE_TTL_SECONDS           = "60"

    # ── Feature toggles ───────────────────────────────────────────────
    PROTOCOL_VERSION                     = "2025-06-18"
    MCPGATEWAY_UI_ENABLED                = "true"
    MCPGATEWAY_UI_AIRGAPPED              = "false"
    MCPGATEWAY_ADMIN_API_ENABLED         = "true"
    ALLOW_PUBLIC_VISIBILITY              = "true"
    MCPGATEWAY_BULK_IMPORT_ENABLED       = "true"
    MCPGATEWAY_BULK_IMPORT_MAX_TOOLS     = "200"
    MCPGATEWAY_BULK_IMPORT_RATE_LIMIT    = "10"
    MCPGATEWAY_A2A_ENABLED               = "true"
    MCPGATEWAY_A2A_MAX_AGENTS            = "100"
    MCPGATEWAY_A2A_DEFAULT_TIMEOUT       = "30"
    MCPGATEWAY_A2A_MAX_RETRIES           = "3"
    MCPGATEWAY_A2A_METRICS_ENABLED       = "true"
    MCPGATEWAY_DIRECT_PROXY_ENABLED      = "false"
    MCPGATEWAY_CATALOG_ENABLED           = "true"
    MCPGATEWAY_CATALOG_FILE              = "mcp-catalog.yml"
    MCPGATEWAY_CATALOG_AUTO_HEALTH_CHECK = "true"
    MCPGATEWAY_CATALOG_CACHE_TTL         = "3600"
    MCPGATEWAY_CATALOG_PAGE_SIZE         = "100"
    TOOLOPS_ENABLED                      = "false"
    MCPGATEWAY_STDIO_TRANSPORT_ENABLED   = "false"
    PLUGINS_CAN_OVERRIDE_RBAC            = "false"
    LLMCHAT_ENABLED                      = "false"
    DEFAULT_ROOTS                        = "[]"
    ALLOWED_ROOTS                        = "[]"

    # ── SSRF protection ───────────────────────────────────────────────
    SSRF_PROTECTION_ENABLED     = "true"
    SSRF_ALLOW_LOCALHOST        = "false"
    SSRF_ALLOW_PRIVATE_NETWORKS = "false"
    SSRF_ALLOWED_NETWORKS       = jsonencode(["10.0.0.0/16"])
    SSRF_DNS_FAIL_CLOSED        = "true"

    # ── Security & CORS ───────────────────────────────────────────────
    ENVIRONMENT            = "production"
    CORS_ENABLED           = "true"
    CORS_ALLOW_CREDENTIALS = "true"
    SKIP_SSL_VERIFY        = "false"

    # ── Security headers ──────────────────────────────────────────────
    SECURITY_HEADERS_ENABLED       = "true"
    X_FRAME_OPTIONS                = "DENY"
    X_CONTENT_TYPE_OPTIONS_ENABLED = "true"
    X_XSS_PROTECTION_ENABLED       = "true"
    X_DOWNLOAD_OPTIONS_ENABLED     = "true"
    HSTS_ENABLED                   = "true"
    HSTS_MAX_AGE                   = "31536000"
    HSTS_INCLUDE_SUBDOMAINS        = "true"
    REMOVE_SERVER_HEADERS          = "true"

    # ── Cookie security ───────────────────────────────────────────────
    SECURE_COOKIES  = "false"
    COOKIE_SAMESITE = "lax"

    # ── Query param auth (disabled) ───────────────────────────────────
    INSECURE_ALLOW_QUERYPARAM_AUTH = "false"

    # ── Identity propagation (disabled) ──────────────────────────────
    IDENTITY_PROPAGATION_ENABLED = "false"

    # ── Content size limits ───────────────────────────────────────────
    CONTENT_MAX_RESOURCE_SIZE = "102400"
    CONTENT_MAX_PROMPT_SIZE   = "10240"

    # ── Logging ───────────────────────────────────────────────────────
    LOG_LEVEL    = "INFO"
    LOG_FORMAT   = "json"
    LOG_TO_FILE  = "false"
    LOG_REQUESTS = "false"

    # ── Audit / metrics ───────────────────────────────────────────────
    AUDIT_TRAIL_ENABLED            = "false"
    PERMISSION_AUDIT_ENABLED       = "false"
    DB_METRICS_RECORDING_ENABLED   = "true"
    METRICS_BUFFER_ENABLED         = "true"
    METRICS_BUFFER_FLUSH_INTERVAL  = "60"
    METRICS_BUFFER_MAX_SIZE        = "1000"
    METRICS_CLEANUP_ENABLED        = "true"
    METRICS_RETENTION_DAYS         = "7"
    METRICS_CLEANUP_INTERVAL_HOURS = "1"
    METRICS_CLEANUP_BATCH_SIZE     = "10000"
    METRICS_ROLLUP_ENABLED         = "true"
    METRICS_ROLLUP_INTERVAL_HOURS  = "1"
    METRICS_ROLLUP_RETENTION_DAYS  = "365"
    ENABLE_METRICS                 = "false"

    # ── Transports ────────────────────────────────────────────────────
    TRANSPORT_TYPE                      = "all"
    MCPGATEWAY_WS_RELAY_ENABLED         = "false"
    MCPGATEWAY_REVERSE_PROXY_ENABLED    = "false"
    SSE_SEND_TIMEOUT                    = "30.0"
    SSE_KEEPALIVE_ENABLED               = "true"
    SSE_KEEPALIVE_INTERVAL              = "30"
    USE_STATEFUL_SESSIONS               = "false"
    JSON_RESPONSE_ENABLED               = "true"
    MCPGATEWAY_SESSION_AFFINITY_ENABLED = "false"

    # ── Federation / health checks ────────────────────────────────────
    FEDERATION_TIMEOUT           = "120"
    HEALTH_CHECK_INTERVAL        = "60"
    HEALTH_CHECK_TIMEOUT         = "5"
    UNHEALTHY_THRESHOLD          = "3"
    MAX_CONCURRENT_HEALTH_CHECKS = "10"
    AUTO_REFRESH_SERVERS         = "false"

    # ── Tool limits ───────────────────────────────────────────────────
    TOOL_TIMEOUT          = "60"
    MAX_TOOL_RETRIES      = "3"
    TOOL_RATE_LIMIT       = "100"
    TOOL_CONCURRENT_LIMIT = "10"

    # ── Plugins ───────────────────────────────────────────────────────
    PLUGINS_ENABLED        = "true"
    PLUGINS_PLUGIN_TIMEOUT = "30"
    PLUGINS_LOG_LEVEL      = "INFO"

    # ── Observability (all disabled) ──────────────────────────────────
    OTEL_ENABLE_OBSERVABILITY = "false"
    OBSERVABILITY_ENABLED     = "false"

    # ── Pagination ────────────────────────────────────────────────────
    PAGINATION_DEFAULT_PAGE_SIZE = "50"
    PAGINATION_MAX_PAGE_SIZE     = "500"
    PAGINATION_CURSOR_ENABLED    = "true"

    # ── Validation ────────────────────────────────────────────────────
    VALIDATION_MAX_REQUESTS_PER_MINUTE = "60"
    VALIDATION_STRICT                  = "true"
    JSON_SCHEMA_VALIDATION_STRICT      = "true"
    SANITIZE_OUTPUT                    = "true"

    # ── Elicitation ───────────────────────────────────────────────────
    MCPGATEWAY_ELICITATION_ENABLED        = "true"
    MCPGATEWAY_ELICITATION_TIMEOUT        = "60"
    MCPGATEWAY_ELICITATION_MAX_CONCURRENT = "100"

    # ── Misc ──────────────────────────────────────────────────────────
    STRUCTURED_LOGGING_ENABLED = "true"
    COMPRESSION_ENABLED        = "true"
    WELL_KNOWN_ENABLED         = "true"
    GLOBAL_CONFIG_CACHE_TTL    = "60"
  }
}

########################################################################
# PostgreSQL
########################################################################

resource "kubernetes_persistent_volume_claim_v1" "postgres" {
  metadata {
    name      = "${local.postgres_app_name}-data"
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
  }

  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = "gp3"

    resources {
      requests = {
        storage = "10Gi"
      }
    }
  }
}

resource "kubernetes_deployment_v1" "postgres" {
  metadata {
    name      = local.postgres_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.postgres_app_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.postgres_app_name
      }
    }

    strategy {
      type = "Recreate"
    }

    template {
      metadata {
        labels = {
          app = local.postgres_app_name
        }
      }

      spec {
        security_context {
          fs_group    = 999
          run_as_user = 999
        }

        container {
          name  = "postgres"
          image = var.postgres_image

          port {
            container_port = 5432
            name           = "postgres"
            protocol       = "TCP"
          }

          env_from {
            secret_ref {
              name = kubernetes_manifest.vault_secret_mcp_postgres.manifest.spec.destination.name
            }
          }

          env {
            name  = "PGDATA"
            value = "/var/lib/postgresql/data/pgdata"
          }

          volume_mount {
            name       = "postgres-data"
            mount_path = "/var/lib/postgresql/data"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "1"
              memory = "1Gi"
            }
          }

          liveness_probe {
            exec {
              command = ["pg_isready", "-U", "mcpuser", "-d", "postgresdb"]
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 6
          }

          readiness_probe {
            exec {
              command = ["pg_isready", "-U", "mcpuser", "-d", "postgresdb"]
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 999
            run_as_group               = 999
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "postgres-data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.postgres.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "postgres" {
  metadata {
    name      = local.postgres_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.postgres_app_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 5432
      target_port = 5432
      protocol    = "TCP"
      name        = "postgres"
    }

    selector = {
      app = local.postgres_app_name
    }
  }
}

########################################################################
# Redis
########################################################################

resource "kubernetes_deployment_v1" "redis" {
  metadata {
    name      = local.redis_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.redis_app_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.redis_app_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.redis_app_name
        }
      }

      spec {
        container {
          name  = "redis"
          image = var.redis_image

          port {
            container_port = 6379
            name           = "redis"
            protocol       = "TCP"
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          liveness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            initial_delay_seconds = 15
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 6
          }

          readiness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            initial_delay_seconds = 5
            period_seconds        = 5
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 999
            run_as_group               = 999
            allow_privilege_escalation = false

            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "redis" {
  metadata {
    name      = local.redis_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.redis_app_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 6379
      target_port = 6379
      protocol    = "TCP"
      name        = "redis"
    }

    selector = {
      app = local.redis_app_name
    }
  }
}

########################################################################
# MCP Context Forge application
########################################################################

resource "kubernetes_deployment_v1" "mcp_context_forge" {
  metadata {
    name      = local.mcp_context_forge_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.mcp_context_forge_app_name
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = local.mcp_context_forge_app_name
      }
    }

    template {
      metadata {
        labels = {
          app = local.mcp_context_forge_app_name
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.mcp_context_forge.metadata[0].name

        container {
          name  = local.mcp_context_forge_app_name
          image = var.mcp_context_forge_image

          port {
            container_port = 4444
            name           = "http"
            protocol       = "TCP"
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.identity.metadata[0].name
            }
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.app.metadata[0].name
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_manifest.vault_secret_mcp_app.manifest.spec.destination.name
            }
          }

          env {
            name = "DATABASE_URL"
            value_from {
              secret_key_ref {
                name = kubernetes_manifest.vault_secret_mcp_database_url.manifest.spec.destination.name
                key  = "DATABASE_URL"
              }
            }
          }

          env {
            name  = "REDIS_URL"
            value = "redis://${kubernetes_service_v1.redis.metadata[0].name}:6379/0"
          }

          resources {
            requests = {
              cpu    = "500m"
              memory = "768Mi"
            }
            limits = {
              cpu    = "2"
              memory = "2Gi"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 4444
            }
            initial_delay_seconds = 120
            period_seconds        = 30
            timeout_seconds       = 70
            failure_threshold     = 10
          }

          readiness_probe {
            http_get {
              path = "/ready"
              port = 4444
            }
            initial_delay_seconds = 30
            period_seconds        = 15
            timeout_seconds       = 70
            failure_threshold     = 8
          }

          security_context {
            run_as_non_root            = true
            run_as_user                = 10001
            run_as_group               = 10001
            allow_privilege_escalation = false
            read_only_root_filesystem  = true

            capabilities {
              drop = ["ALL"]
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_deployment_v1.postgres,
    kubernetes_deployment_v1.redis,
    kubernetes_manifest.vault_secret_mcp_postgres,
    kubernetes_manifest.vault_secret_mcp_app,
    kubernetes_manifest.vault_secret_mcp_database_url,
  ]
}

resource "kubernetes_service_v1" "mcp_context_forge" {
  metadata {
    name      = local.mcp_context_forge_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    labels = {
      app = local.mcp_context_forge_app_name
    }
  }

  spec {
    type = "ClusterIP"

    port {
      port        = 80
      target_port = 4444
      protocol    = "TCP"
      name        = "http"
    }

    selector = {
      app = local.mcp_context_forge_app_name
    }
  }
}

resource "kubernetes_ingress_v1" "mcp_context_forge" {
  metadata {
    name      = local.mcp_context_forge_app_name
    namespace = kubernetes_namespace_v1.ai_system.metadata[0].name
    annotations = {
      "alb.ingress.kubernetes.io/scheme"                       = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"                  = "ip"
      "alb.ingress.kubernetes.io/inbound-cidrs"                = join(",", var.inbound_cidrs_for_lbs)
      "alb.ingress.kubernetes.io/load-balancer-attributes"     = "idle_timeout.timeout_seconds=1800"
      "alb.ingress.kubernetes.io/success-codes"                = "200,201,404"
      "alb.ingress.kubernetes.io/tags"                         = "Environment=${var.environment},Project=${var.project_name},ManagedBy=Terraform"
      "alb.ingress.kubernetes.io/healthcheck-path"             = "/health"
      "alb.ingress.kubernetes.io/healthcheck-interval-seconds" = "30"
      "alb.ingress.kubernetes.io/healthcheck-timeout-seconds"  = "5"
    }
    labels = {
      app = local.mcp_context_forge_app_name
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
              name = kubernetes_service_v1.mcp_context_forge.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }

  depends_on = [
    kubernetes_deployment_v1.mcp_context_forge,
  ]
}
