#!/bin/bash

mkdir -p secrets

export VAULT_FORMAT=json
KEYS=$(kubectl exec -it -n vault vault-0 -- vault operator init)
echo $KEYS > secrets/vault-init.txt
kubectl exec -it -n vault vault-0 -- vault status