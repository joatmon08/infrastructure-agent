#!/bin/bash

kubectl exec -n vault vault-0 -- vault operator init > secrets/vault-init.txt
kubectl exec -n vault vault-0 -- vault status