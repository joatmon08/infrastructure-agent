variable "inbound_cidrs_for_lbs" {
  type        = list(string)
  description = "Comma-separated list of inbound CIDRs"
  default     = ["0.0.0.0/0"]
}

variable "tfc_organization" {
  type        = string
  description = "TFC organization name"
}

variable "tfc_base_workspace" {
  type        = string
  description = "TFC base workspace name"
  default     = "base"
}

variable "vault_token" {
  type        = string
  description = "Vault token"
  sensitive   = true
}