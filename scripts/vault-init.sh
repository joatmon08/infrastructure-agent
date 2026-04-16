#!/bin/bash

kubectl exec -n vault vault-0 -- vault operator init > secrets/vault-init.txt
kubectl exec -n vault vault-0 -- vault status

SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)      

source secrets.env

vault audit enable file file_path=stdout

vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
vault plugin info secret vault-plugin-secrets-oauth-token-exchange