# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

This is a Terraform infrastructure repository that deploys an AWS EKS-based platform with HashiCorp Vault, agent workloads, and MCP Context Forge. All infrastructure is managed through HCP Terraform.

## Workspace Deployment Order

Workspaces must be deployed in this order due to state dependencies:

1. **`txc-base`** (`terraform/base`) — VPC, EKS cluster, ECR repositories, KMS keys, EKS add-ons
2. **`txc-kubernetes`** (`terraform/kubernetes`) — Vault Helm release, ingresses, EFS, TLS, Vault Secrets Operator; depends on `txc-base`
3. **`txc-vault`** (`terraform/vault`) — Vault auth methods, OIDC provider, identity secrets engine, custom plugin; depends on `txc-base`, `txc-kubernetes`
4. **`txc-helloworld`** (`terraform/helloworld`) — Agent application deployments; depends on `txc-base`, `txc-kubernetes`, `txc-vault`
5. **`txc-mcp-context-forge`** (`terraform/mcp-context-forge`) — MCP Context Forge gateway, PostgreSQL, Redis in the `ai-system` namespace; depends on `txc-base`

## Vault Initialization

Vault must be initialized after the `txc-kubernetes` workspace applies successfully:

```bash
aws eks update-kubeconfig --region us-east-1 --name txc-ai
bash scripts/vault-init.sh
```

This stores unseal keys and the root token in `secrets/vault-init.json` and registers the custom OAuth token-exchange plugin. The `vault_token` workspace variable in `txc-kubernetes` and `txc-vault` must be updated with the root token after initialization.

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

After the `txc-vault` workspace applies successfully, run the end-to-end tests to verify the cluster and Vault configuration:

```bash
source secrets.env && uv run pytest
```

The tests require `KUBERNETES_CONTEXT`, `VAULT_ADDR`, and `VAULT_TOKEN` to be set in `secrets.env`. They cover:

- **`kubernetes` mark** — GPU node presence, Vault server pods (3 replicas), Vault agent injector, and Vault Secrets Operator are all `Running`
- **`vault` mark** — Vault is initialized, unsealed, and the `vault-plugin-secrets-oauth-token-exchange` plugin is registered

## Import Blocks

If adopting pre-existing AWS resources, add temporary `import` blocks in `terraform/base/imports.tf`, run a plan/apply to complete the import, then immediately remove the blocks. Do not leave import blocks in place after a successful import.
