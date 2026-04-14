locals {
  client_username = data.terraform_remote_state.kubernetes.outputs.client_username
  end_user        = data.terraform_remote_state.kubernetes.outputs.end_user_username
  vault_endpoint  = data.terraform_remote_state.kubernetes.outputs.vault_endpoint

  test_client_redirect_uris = data.terraform_remote_state.kubernetes.outputs.test_client_redirect_uris
}