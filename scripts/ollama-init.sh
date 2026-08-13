#!/bin/bash

kubectl exec -n ollama -it $(kubectl get pods -n ollama -l app=ollama -o jsonpath='{.items[0].metadata.name}') -- ollama pull llama3.2:3b