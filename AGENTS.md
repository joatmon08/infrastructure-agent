# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Repository Overview

This is a Terraform infrastructure repository that deploys an AWS EKS-based platform with HashiCorp Vault, agent workloads, and MCP Context Forge. All infrastructure is managed through HCP Terraform.

## Workspace Deployment Order

Workspaces must be deployed in this order due to state dependencies:

1. **`txc-base`** (`terraform/base`) — VPC, EKS cluster (AMD64 managed node group), ECR repositories, KMS keys, EKS add-ons (CoreDNS, kube-proxy, vpc-cni, EBS CSI driver, EFS CSI driver), AWS Load Balancer Controller
2. **`txc-kubernetes`** (`terraform/kubernetes`) — Vault Helm release, ALB ingresses for `helloworld-agent-server` and `test-client`, EFS file system and Kubernetes Job for Vault plugin loading, KMS key for Vault auto-unseal, TLS, Vault Secrets Operator; depends on `txc-base`
3. **`txc-vault`** (`terraform/vault`) — Vault auth methods, OIDC provider, identity secrets engine, custom `vault-plugin-secrets-oauth-token-exchange` plugin; depends on `txc-base`, `txc-kubernetes`
4. **`txc-helloworld`** (`terraform/helloworld`) — `helloworld-agent-server` and `test-client` Kubernetes deployments/services, Vault Secrets Operator CRDs (`VaultAuth`, `VaultDynamicSecret`) for secret injection; depends on `txc-base`, `txc-kubernetes`, `txc-vault`
5. **`txc-mcp-context-forge`** (`terraform/mcp-context-forge`) — MCP Context Forge gateway, PostgreSQL 17, Redis in the `ai-system` namespace; depends on `txc-base`

## Required Workspace Variables

### `txc-kubernetes`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |
| `inbound_cidrs_for_lbs` | list(string) HCL | no | CIDR blocks for load balancer access |

### `txc-vault`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |
| `vault_token` | string (sensitive) | yes | Vault root token from initialization |
| `client_agents` | map HCL | yes | Map of client agents with `k8s_namespace` and `claims` |

### `txc-helloworld`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |

### `txc-mcp-context-forge`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |
| `mcp_admin_email` | string | no | Admin email (default: `admin@example.com`) |

## Vault Initialization

Vault must be initialized after the `txc-kubernetes` workspace applies successfully:

```bash
aws eks update-kubeconfig --region us-east-1 --name txc-ai
bash scripts/vault-init.sh
```

This stores unseal keys and the root token in `secrets/vault-init.json` and registers the custom OAuth token-exchange plugin. The `vault_token` workspace variable in `txc-kubernetes` and `txc-vault` must be updated with the root token after initialization.

## GitHub Actions Workflows

Two workflows in `.github/workflows/` build and push container images to GitHub Container Registry (GHCR). They are triggered by Git tags and `workflow_dispatch`.

| Workflow | Trigger tag | Image pushed |
|---|---|---|
| `build-helloworld.yml` | `helloworld-v*` | `ghcr.io/<owner>/helloworld` |
| `build-test-client.yml` | `testclient-v*` | `ghcr.io/<owner>/test-client` |

The `txc-helloworld` workspace defaults to pulling `ghcr.io/joatmon08/helloworld:latest` and `ghcr.io/joatmon08/test-client:latest`. Override `helloworld_agent_image` and `test_client_image` workspace variables to pin a specific tag.

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

`secrets.env` must export:

| Variable | Description |
|---|---|
| `KUBERNETES_CONTEXT` | `kubectl` context name for the EKS cluster |
| `VAULT_ADDR` | Vault server URL |
| `VAULT_TOKEN` | Vault root token |
| `VAULT_SKIP_VERIFY` | Set to a non-empty value to skip TLS verification |

The tests cover:

- **`kubernetes` mark** — Vault server pods (3 replicas), Vault agent injector, and Vault Secrets Operator are all `Running`
- **`vault` mark** — Vault is initialized, unsealed, and the `vault-plugin-secrets-oauth-token-exchange` plugin is registered

## Import Blocks

If adopting pre-existing AWS resources, add temporary `import` blocks in `terraform/base/imports.tf`, run a plan/apply to complete the import, then immediately remove the blocks. Do not leave import blocks in place after a successful import.
