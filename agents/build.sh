#!/bin/bash

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 224382219437.dkr.ecr.us-east-1.amazonaws.com

cd helloworld

docker buildx build --platform linux/amd64 --file Dockerfile --tag 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-helloworld-agent:$(git rev-parse HEAD) .
docker push 224382219437.dkr.ecr.us-east-1.amazonaws.com/infra-agent-helloworld-agent:$(git rev-parse HEAD)