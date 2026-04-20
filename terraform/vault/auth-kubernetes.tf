data "kubernetes_service_account_v1" "vault_auth" {
  metadata {
    name      = data.terraform_remote_state.kubernetes.outputs.helm_vault_name
    namespace = data.terraform_remote_state.kubernetes.outputs.helm_vault_namespace
  }
}

resource "kubernetes_secret_v1" "vault_auth" {
  metadata {
    name      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
    namespace = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    annotations = {
      "kubernetes.io/service-account.name"      = data.kubernetes_service_account_v1.vault_auth.metadata.0.name
      "kubernetes.io/service-account.namespace" = data.kubernetes_service_account_v1.vault_auth.metadata.0.namespace
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = data.terraform_remote_state.kubernetes.outputs.cluster_endpoint
  kubernetes_ca_cert     = kubernetes_secret_v1.vault_auth.data["ca.crt"]
  token_reviewer_jwt     = kubernetes_secret_v1.vault_auth.data.token
  disable_iss_validation = "true"
}

resource "kubernetes_service_account_v1" "client_agents" {
  for_each = var.client_agents
  metadata {
    name = each.key
    labels = {
      app = each.key
    }
  }
}

resource "kubernetes_secret_v1" "client_agents_tokens" {
  for_each = var.client_agents
  metadata {
    name = "${each.key}-token"
    labels = {
      app = each.key
    }
    annotations = {
      "kubernetes.io/service-account.name" = each.key
    }
  }

  type = "kubernetes.io/service-account-token"
}

resource "vault_identity_entity_alias" "client_agents" {
  for_each       = var.client_agents
  name           = kubernetes_service_account_v1.client_agents[each.key].metadata[0].uid
  mount_accessor = vault_auth_backend.kubernetes.accessor
  canonical_id   = vault_identity_entity.client_agents[each.key].id
}

resource "vault_kubernetes_auth_backend_role" "client_agents" {
  for_each                         = var.client_agents
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = each.key
  bound_service_account_names      = [each.key]
  bound_service_account_namespaces = [each.value.k8s_namespace]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.actor_token[each.key].name, vault_policy.agent_oidc_client.name, vault_policy.oauth_exchange_token[each.key].name]
}