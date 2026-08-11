#!/bin/bash

VAULT_STATUS=$(kubectl exec -n vault vault-0 -- vault status -format=json 2>/dev/null)
INITIALIZED=$(echo "$VAULT_STATUS" | jq -r '.initialized')
SEALED=$(echo "$VAULT_STATUS" | jq -r '.sealed')

if [ "$INITIALIZED" = "true" ] && [ "$SEALED" = "false" ]; then
  echo "Vault is already initialized and unsealed, skipping init."
else
  echo "Vault is not ready (initialized=${INITIALIZED}, sealed=${SEALED}), initializing..."
  cp secrets/vault-init.json secrets/vault-init.json.bak 2>/dev/null || true
  kubectl exec -n vault vault-0 -- vault operator init -format=json > secrets/vault-init.json

  echo "Waiting for Vault to be ready..."
  until kubectl exec -n vault vault-0 -- vault status -format=json 2>/dev/null | jq -e '.initialized == true and .sealed == false' > /dev/null; do
    echo "  Vault not ready yet, retrying in 5 seconds..."
    sleep 5
  done
  echo "Vault is ready."
fi

export VAULT_ADDR=$(cd terraform/kubernetes && terraform output -raw vault_endpoint)
export VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json)
export VAULT_SKIP_VERIFY=true

echo "Waiting for Vault API to be reachable at ${VAULT_ADDR}..."
until curl -sk -o /dev/null -w "%{http_code}" "${VAULT_ADDR}/v1/sys/health" | grep -qE "^(200|429|472|473)$"; do
  echo "  Vault API not ready yet (HTTP $(curl -sk -o /dev/null -w '%{http_code}' "${VAULT_ADDR}/v1/sys/health")), retrying in 5 seconds..."
  sleep 5
done
echo "Vault API is reachable."

vault audit enable file file_path=stdout

SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)   
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
vault plugin info secret vault-plugin-secrets-oauth-token-exchange