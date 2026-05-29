#!/bin/bash

ECR_URI=$(cd terraform/base && terraform output -raw ecr_repository_uri)

cd Dockerfiles

aws ecr get-login-password --region us-east-1 | podman login --username AWS --password-stdin ${ECR_URI}
podman build --platform linux/amd64 --file Dockerfile.langflow --tag ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD) .
podman push ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD)