output "vault_endpoint" {
  description = "Vault endpoint"
  value       = local.vault_endpoint
}

output "helm_vault_name" {
  description = "Name of Helm release for Vault"
  value       = helm_release.vault.name
}

output "helm_vault_namespace" {
  description = "Namespace of Helm release for Vault"
  value       = helm_release.vault.namespace
}

output "vault_plugins_efs_id" {
  description = "EFS file system ID for Vault plugins"
  value       = aws_efs_file_system.vault_plugins.id
}

output "vault_plugins_pvc_name" {
  description = "PVC name for Vault plugins"
  value       = kubernetes_persistent_volume_claim_v1.vault_plugins.metadata[0].name
}

output "vault_plugin_loader_job_name" {
  description = "Name of the plugin loader job"
  value       = length(var.vault_plugins) > 0 ? kubernetes_job_v1.vault_plugin_loader[0].metadata[0].name : "no-plugins-configured"
}

output "end_user_username" {
  description = "The username for the end user"
  value       = local.end_user
}


output "test_client_url" {
  description = "URL to access test-client"
  value       = kubernetes_service_v1.test_client.status != null ? "http://${kubernetes_service_v1.test_client.status.0.load_balancer.0.ingress.0.hostname}" : ""
}

output "helloworld_agent_server_url" {
  description = "URL to access helloworld-agent-server"
  value       = "http://${kubernetes_ingress_v1.helloworld_agent_server.status.0.load_balancer.0.ingress.0.hostname}"
}


output "ca_cert" {
  description = "Output CA certificate for verification"
  value       = base64encode(tls_self_signed_cert.ca_cert.cert_pem)
  sensitive   = true
}

output "client_username" {
  description = "Client username for test-client"
  value       = local.client_username
}

output "test_client_redirect_uris" {
  description = "Test client redirect URIs"
  value       = local.test_client_redirect_uris
}

output "vault_kms_key_id" {
  description = "KMS key ID used for Vault auto-unseal"
  value       = aws_kms_key.vault.key_id
}

output "vault_kms_key_arn" {
  description = "KMS key ARN used for Vault resources"
  value       = aws_kms_key.vault.arn
}

output "vault_iam_role_arn" {
  description = "IAM role ARN for the Vault service account"
  value       = aws_iam_role.vault.arn
}

output "vault_iam_role_name" {
  description = "IAM role name for the Vault service account"
  value       = aws_iam_role.vault.name
}

output "cluster_endpoint" {
  description = "Kubernetes cluster endpoint"
  value       = data.terraform_remote_state.base.outputs.cluster_endpoint
}

output "cluster_name" {
  description = "Kubernetes cluster name"
  value       = data.terraform_remote_state.base.outputs.cluster_name
}

output "cluster_certificate_authority_data" {
  description = "Kubernetes cluster certificate authority data"
  value       = data.terraform_remote_state.base.outputs.cluster_certificate_authority_data
  sensitive   = true
}
