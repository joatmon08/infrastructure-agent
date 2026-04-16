variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
}

variable "tfc_kubernetes_workspace" {
  type        = string
  description = "TFC kubernetes workspace name"
  default     = "kubernetes"
}

variable "vault_token" {
  type        = string
  description = "Vault token"
  sensitive   = true
}

variable "client_agents" {
  type = map(object({
    k8s_namespace = string,
    claims        = map(string),
  }))
  description = "Client agents that request actor tokens. Must include Kubernetes namespace and claims added to token."
}

variable "oauth_token_exchange_secrets_path" {
  type        = string
  description = "Vault path for oauth token exchange secrets"
  default     = "sts"
}