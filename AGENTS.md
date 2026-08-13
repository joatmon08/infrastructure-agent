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
5. **`txc-mcp-context-forge`** (`terraform/mcp-context-forge`) — MCP Context Forge gateway, PostgreSQL 17, Redis in the `ai-system` namespace; depends on `txc-base`, `txc-kubernetes`

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
| `mcp_context_forge_jwt_secret` | string (sensitive) | yes | JWT signing secret for MCP Context Forge (≥32 bytes) |
| `mcp_context_forge_auth_encryption_secret` | string (sensitive) | yes | Encryption secret for stored credentials (≥32 bytes) |

Generate both secrets with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Run the command twice — once for `mcp_context_forge_jwt_secret` and once for `mcp_context_forge_auth_encryption_secret`. Set each as a sensitive workspace variable in `txc-vault`.

### `txc-helloworld`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |

### `txc-mcp-context-forge`

| Variable | Type | Required | Description |
|---|---|---|---|
| `tfc_organization` | string | yes | HCP Terraform organization name |
| `tfc_kubernetes_workspace` | string | no | TFC kubernetes workspace name (default: `txc-kubernetes`) |
| `mcp_admin_email` | string | no | Admin email (default: `admin@example.com`) |
| `vault_token` | string (sensitive) | yes | Vault root token from initialization |

## Vault Initialization

Vault must be initialized after the `txc-kubernetes` workspace applies successfully:

```bash
aws eks update-kubeconfig --region us-east-1 --name txc-ai
bash scripts/vault-init.sh
```

This stores unseal keys and the root token in `secrets/vault-init.json` and registers the custom OAuth token-exchange plugin. The `vault_token` workspace variable in `txc-kubernetes` and `txc-vault` must be updated with the root token after initialization.

## Agent Development Notes

The summarizer agent in [`agents/summarizer`](agents/summarizer) now supports both authenticated and unauthenticated local startup:

- set `AUTH_ENABLED=true` with `OPENID_CONNECT_URL` to enforce Vault-backed JWT validation
- set `AUTH_ENABLED=false` to disable auth for local integration and testing
- the default bind host remains `127.0.0.1`; container runtimes must explicitly override it when binding on all interfaces is required
- after deploying Ollama for the summarizer via Terraform, preload `llama3.2:3b` with [`scripts/ollama-init.sh`](scripts/ollama-init.sh)

Its smoke and request-flow tests live in [`agents/summarizer/tests/test_summarizer_app.py`](agents/summarizer/tests/test_summarizer_app.py:1).

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

After the `txc-vault` workspace applies successfully, run the end-to-end tests to verify the cluster, Vault configuration, and deployed summarizer agent. If the summarizer depends on Ollama, preload `llama3.2:3b` first with [`scripts/ollama-init.sh`](scripts/ollama-init.sh).

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
| `SUMMARIZER_URL` | Base URL of the deployed summarizer agent |

The tests cover:

- **`kubernetes` mark** — Vault server pods (3 replicas), Vault agent injector, and Vault Secrets Operator are all `Running`
- **`vault` mark** — Vault is initialized, unsealed, and the `vault-plugin-secrets-oauth-token-exchange` plugin is registered
- **`summarizer` mark** — the summarizer agent card is served and its A2A JSON-RPC endpoint returns a completed summary task

## Vault Static Secrets

After `txc-vault` applies, the following static secrets are stored in Vault KV v2. These are written by Terraform using ephemeral random passwords and are never printed to output.

### `credentials/` KV mount — end-user credentials

| Vault path | Fields | Description |
|---|---|---|
| `credentials/data/end-user` | `username`, `password` | Userpass credentials for the `end-user` Vault login |

Retrieve the password for the OIDC login flow:

```bash
source secrets.env
vault kv get -field=password credentials/end-user
```

### `mcp-context-forge/` KV mount — MCP Context Forge secrets

The Terraform deployment explicitly disables SSO with `SSO_ENABLED=false`, so the admin UI uses the local email/password sign-in flow backed by Vault-managed credentials.

| Vault path | Fields | Description |
|---|---|---|
| `mcp-context-forge/data/postgres` | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | PostgreSQL credentials for the `mcp-postgres` service |
| `mcp-context-forge/data/app` | `PLATFORM_ADMIN_PASSWORD`, `DEFAULT_USER_PASSWORD`, `BASIC_AUTH_PASSWORD`, `JWT_SECRET_KEY`, `AUTH_ENCRYPTION_SECRET` | MCP Context Forge application secrets |
| `mcp-context-forge/data/database-url` | `DATABASE_URL` | Full PostgreSQL connection string for the MCP Context Forge app |

`PLATFORM_ADMIN_PASSWORD`, `DEFAULT_USER_PASSWORD`, and `BASIC_AUTH_PASSWORD` are generated as separate Vault values.

These secrets are synced to Kubernetes in the `ai-system` namespace via Vault Secrets Operator `VaultStaticSecret` CRDs:

| Kubernetes secret | Vault path |
|---|---|
| `mcp-postgres` | `mcp-context-forge/data/postgres` |
| `mcp-context-forge` | `mcp-context-forge/data/app` |
| `mcp-database-url` | `mcp-context-forge/data/database-url` |

## Import Blocks

If adopting pre-existing AWS resources, add temporary `import` blocks in `terraform/base/imports.tf`, run a plan/apply to complete the import, then immediately remove the blocks. Do not leave import blocks in place after a successful import.
