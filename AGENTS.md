# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

This is a Terraform infrastructure repository that deploys an AWS EKS-based platform with HashiCorp Vault, agent workloads, and a RAG stack. All infrastructure is managed through HCP Terraform.

## Workspace Deployment Order

Workspaces must be deployed in this order due to state dependencies:

1. **`base`** (`terraform/base`) — VPC, EKS cluster, ECR repositories, KMS keys, EKS add-ons
2. **`kubernetes`** (`terraform/kubernetes`) — Vault Helm release, ingresses, EFS, TLS, Vault Secrets Operator; depends on `base`
3. **`vault`** (`terraform/vault`) — Vault auth methods, OIDC provider, identity secrets engine, custom plugin; depends on `base`, `kubernetes`
4. **`helloworld`** (`terraform/helloworld`) — Agent application deployments; depends on `base`, `kubernetes`, `vault`
5. **`rag`** (`terraform/rag`) — Ollama, LangFlow, OpenSearch on GPU node group; depends on `base`
6. **`mcp-context-forge`** (`terraform/mcp-context-forge`) — MCP Context Forge gateway, PostgreSQL, Redis in the `ai-system` namespace; depends on `base`

## Vault Initialization

Vault must be initialized after the `kubernetes` workspace applies successfully:

```bash
aws eks update-kubeconfig --region us-east-1 --name infra-agent
bash scripts/vault-init.sh
```

This stores unseal keys and the root token in `secrets/vault-init.json` and registers the custom OAuth token-exchange plugin. The `vault_token` workspace variable in `kubernetes` and `vault` workspaces must be updated with the root token after initialization.

## Terraform CLI

Always use `-no-color` with Terraform commands:

```bash
terraform init -no-color
terraform validate -no-color
terraform plan -no-color
terraform apply -no-color
```

## HCP Terraform Runs

Runs are triggered by `git push` for workspaces with VCS-connected trigger patterns. For workspaces that need a manual trigger (e.g. after a dependency workspace applies), start runs with `tfctl`:

```bash
tfctl run start <workspace-name> --message="<message> - Approved with IBM Bob"
```

## End-to-End Tests

After the `vault` workspace applies successfully, run the end-to-end tests to verify the cluster and Vault configuration:

```bash
source secrets.env && uv run pytest
```

The tests require `KUBERNETES_CONTEXT`, `VAULT_ADDR`, and `VAULT_TOKEN` to be set in `secrets.env`. They cover:

- **`kubernetes` mark** — GPU node presence, Vault server pods (3 replicas), Vault agent injector, and Vault Secrets Operator are all `Running`
- **`vault` mark** — Vault is initialized, unsealed, and the `vault-plugin-secrets-oauth-token-exchange` plugin is registered

## Import Blocks

If adopting pre-existing AWS resources, add temporary `import` blocks in `terraform/base/imports.tf`, run a plan/apply to complete the import, then immediately remove the blocks. Do not leave import blocks in place after a successful import.