#!/usr/bin/env bash

OLLAMA_POD=$(kubectl get pods -l app=ollama -o name)

kubectl exec ${OLLAMA_POD} -- ollama pull granite4:tiny-h
kubectl exec ${OLLAMA_POD} -- ollama pull granite-embedding:30m

kubectl exec ${OLLAMA_POD} -- ollama list