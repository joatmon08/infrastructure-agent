#!/bin/bash

ECR_URI=$(cd terraform/base && terraform output -raw ecr_repository_uri)

cd Dockerfiles

aws ecr get-login-password --region us-east-1 | podman login --username AWS --password-stdin ${ECR_URI}
podman buildx build --no-cache --platform linux/amd64 -f Dockerfile.langflow -t infra-agent-langflow:latest .
podman tag infra-agent-langflow:latest ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD)
podman push --format v2s2 ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD)