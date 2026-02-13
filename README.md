# infrastructure-agent Example Repository

This example repository includes demo code for:

- [LangFlow](https://www.langflow.org/), OpenSearch, Ollama (with Granite 4) deployed on AWS EKS
- Agents using [Agent2Agent protocol](https://a2a-protocol.org/latest/) and [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/secrets/identity/oidc-provider) as an OIDC provider

## Set up infrastructure

Go to the `/terraform` directory.

Set up credentials for AWS.

Run `terraform init`, `terraform plan`, and `terraform apply`.

> Note: This will create an EKS cluster in auto-mode and HCP Vault cluster.
> It was originally deployed with HCP Terraform.

Go to the `/kubernetes` directory.

Run `kubectl apply -f auto-mode.yaml`. This will set up the rest of auto-mode.

## LangFlow

Update `build.sh` to the correct ECR repository.

Build the images and push them to ECR.

```sh
bash build.sh
```

Go to `/kubernetes` and deploy the following:

```sh
kubectl apply -f ollama.yaml
kubectl apply -f langflow-ingress.yaml
kubectl apply -f terraform-mcp-server.yaml
```

Go to `/helm` and deploy the following:

```sh
bash langflow.sh
bash opensearch.sh
```

This creates a set of pods for LangFlow, Ollama, OpenSearch, and the Terraform MCP Server.

## Agent authorization with Vault

Update `agents/build.sh` to the correct ECR repository.

Build the images and push them to ECR.

```sh
cd agents
bash build.sh
```

Go to the `/kubernetes` directory.

Deploy the following:

```sh
kubectl apply -f helloworld-agent.yaml
kubectl apply -f test-client.yaml
```

If you don't want to deploy the test-client to Kubernetes, you can run it locally with:

```sh
OPENID_CONNECT_PROVIDER_NAME=agent OPENID_CONNECT_CLIENT_NAME=agent AGENT_URL=${KUBERNETES_INGRESS_FOR_HELLOWORLD} python agents/test-client/__main__.py
```