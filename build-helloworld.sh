#!/bin/bash

ECR_URI=$(cd terraform/base && terraform output -raw ecr_repository_uri)

aws ecr get-login-password --region us-east-1 | podman login --username AWS --password-stdin ${ECR_URI}

cd agents/helloworld

podman buildx build --platform linux/amd64 --file Dockerfile --tag ${ECR_URI}/infra-agent-helloworld-agent:$(git rev-parse HEAD) .
podman push ${ECR_URI}/infra-agent-helloworld-agent:$(git rev-parse HEAD)

cd ../test-client

podman buildx build --platform linux/amd64 --file Dockerfile --tag ${ECR_URI}/infra-agent-test-client:$(git rev-parse HEAD) .
podman push ${ECR_URI}/infra-agent-test-client:$(git rev-parse HEAD)