pid_file = "./pidfile"

log_file = "./vault-agent.log"

exit_after_auth = true

vault {
  tls_skip_verify = true
}

auto_auth {
  method {
    type = "token_file"

    config = {
      token_file_path = "./.vault-token"
    }
  }
}

cache {}

template_config {
  exit_on_retry_failure = true
}

template {
  source = "vault-agent/client_secrets.json.tmpl"
  destination = "client_secrets.json"
} 

template {
  source = "vault-agent/oidc_provider.json.tmpl"
  destination = "oidc_provider.json"
} 