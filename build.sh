#!/bin/bash

cd Dockerfiles

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 224382219437.dkr.ecr.us-east-1.amazonaws.com 

docker build --file Dockerfile.langflow --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-langflow:$(git rev-parse HEAD) --push .
docker build --file Dockerfile.ollama --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-ollama:$(git rev-parse HEAD) --push .
docker build --file Dockerfile.opensearch --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-opensearch:$(git rev-parse HEAD) --push .