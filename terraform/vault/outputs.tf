output "end_user_password_path" {
  description = "Path to the end user password in Vault KV store"
  value       = "${vault_mount.credentials.path}/data/${vault_kv_secret_v2.end_user_password.name}"
}

output "openid_connect_url" {
  description = "OpenID Connect URL for the helloworld agent"
  value       = "${local.vault_endpoint}/v1/identity/oidc/provider/${vault_identity_oidc_provider.agent.name}/.well-known/openid-configuration"
}

output "vault_kubernetes_auth_backend_path" {
  description = "Path of the Kubernetes auth backend"
  value       = vault_auth_backend.kubernetes.path
}

output "vault_userpass_auth_backend_path" {
  description = "Path of the userpass auth backend"
  value       = vault_auth_backend.userpass.path
}