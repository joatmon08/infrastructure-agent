#!/bin/bash

cd Dockerfiles

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 224382219437.dkr.ecr.us-east-1.amazonaws.com 
docker buildx build --platform linux/amd64 --file Dockerfile.ollama --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-ollama:$(git rev-parse HEAD) .
docker buildx build --platform linux/amd64 --file Dockerfile.langflow --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-langflow:$(git rev-parse HEAD) .

docker push 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-ollama:$(git rev-parse HEAD)
docker push 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-langflow:$(git rev-parse HEAD)