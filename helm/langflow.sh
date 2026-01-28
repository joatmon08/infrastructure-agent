#!/bin/bash

helm repo add langflow https://langflow-ai.github.io/langflow-helm-charts
helm update

helm install langflow langflow/langflow-ide -f langflow.yaml -f langflow-secret.yaml