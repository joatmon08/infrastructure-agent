#!/bin/bash

kubectl exec -n vault vault-0 -- vault operator init -format=json > secrets/vault-init.json
kubectl exec -n vault vault-0 -- vault status

export VAULT_ADDR=$(cd terraform/kubernetes && terraform output -raw vault_endpoint)
export VAULT_TOKEN=$(cat secrets/vault-init.json | jq -r .root_token)
export VAULT_SKIP_VERIFY=true

echo 'export VAULT_ADDR=$(cd terraform/kubernetes && terraform output -raw vault_endpoint)
export VAULT_TOKEN=$(cat secrets/vault-init.json | jq -r .root_token)
export VAULT_SKIP_VERIFY=true' > secrets.env

vault audit enable file file_path=stdout

SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)   
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
vault plugin info secret vault-plugin-secrets-oauth-token-exchange