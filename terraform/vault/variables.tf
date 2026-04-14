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