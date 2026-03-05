#!/bin/bash

cd Dockerfiles

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ${ECR_URI} 
docker buildx build --platform linux/amd64 --file Dockerfile.ollama --tag ${ECR_URI}/infra-agent-ollama:$(git rev-parse HEAD) .
docker buildx build --platform linux/amd64 --file Dockerfile.langflow --tag ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD) .

docker push ${ECR_URI}/infra-agent-ollama:$(git rev-parse HEAD)
docker push ${ECR_URI}/infra-agent-langflow:$(git rev-parse HEAD)