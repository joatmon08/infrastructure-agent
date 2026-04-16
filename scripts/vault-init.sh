#!/bin/bash

mkdir -p secrets

KEYS=$(kubectl exec -it -n vault vault-0 -- vault operator init)
echo $KEYS > secrets/vault-init.txt
kubectl exec -it -n vault vault-0 -- vault status