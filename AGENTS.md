# Automated Deployment Guide for AI Agents

This guide documents the automated deployment workflow for the infrastructure-agent repository using the Terraform MCP server and helper scripts.

## Prerequisites

- HCP Terraform organization and project configured
- AWS credentials configured via environment variables or AWS CLI
- Terraform MCP server connected
- `kubectl` configured for EKS cluster access

## Deployment Workflow

### 1. Deploy Base Infrastructure

The base workspace should already be deployed with:
- EKS cluster
- VPC and networking
- ECR repositories
- AWS KMS for Vault auto-unseal
- GPU node group for ML workloads

### 2. Deploy Kubernetes Workspace

**Automated Steps:**

```bash
# Create run via Terraform MCP server
# Use tool: create_run
# Parameters:
#   - terraform_org_name: "your-org-name"
#   - workspace_name: "kubernetes"
#   - message: "Deploy Kubernetes components - Approved with IBM Bob"

# Monitor the run
bash scripts/check-run-status.sh <run-id> 30 20

# If plan succeeds, apply via Terraform MCP server
# Use tool: action_run
# Parameters:
#   - run_id: "<run-id>"
#   - run_action: "apply"
#   - comment: "Applying Kubernetes deployment - Approved with IBM Bob"

# Monitor apply
bash scripts/check-run-status.sh <run-id> 30 20
```

**Common Issues:**

1. **vault-plugin-loader job timeout**
   - **Symptom**: Job doesn't complete within 5-minute timeout
   - **Cause**: EFS mount failure with DNS resolution error
   - **Resolution**: Retry the run - the job typically succeeds on second attempt

2. **TLS certificate verification failures**
   - **Symptom**: Vault pods restarting with `x509: certificate signed by unknown authority`
   - **Cause**: Stale TLS certificates from previous deployment
   - **Resolution**: Destroy and redeploy kubernetes workspace to generate fresh certificates

### 3. Initialize Vault

**Manual Steps Required:**

```bash
# Configure kubectl for your EKS cluster
aws eks update-kubeconfig --region <region> --name <cluster-name>

# Initialize Vault
bash scripts/vault-init.sh
```

This creates `secrets/vault-init.json` with:
- Root token
- Recovery keys (for AWS KMS auto-unseal)

**What the script does:**
- Initializes Vault with 5 recovery shares, threshold of 3
- Enables audit logging
- Registers vault-plugin-secrets-oauth-token-exchange plugin
- Exports VAULT_ADDR, VAULT_TOKEN, VAULT_SKIP_VERIFY

### 4. Deploy Vault Workspace

**Automated Steps:**

```bash
# Extract root token from vault-init.json
# Update vault workspace variable: vault_token (sensitive)

# Create run via Terraform MCP server
# Use tool: create_run
# Parameters:
#   - terraform_org_name: "your-org-name"
#   - workspace_name: "vault"
#   - message: "Deploy Vault OIDC configuration - Approved with IBM Bob"

# Monitor and apply
bash scripts/check-run-status.sh <run-id> 30 20
```

**What gets deployed:**
- Vault OIDC provider configuration
- Identity secrets engine
- Kubernetes authentication backend
- Token roles for client agents
- Userpass authentication for end-user
- OIDC roles and scopes for Agent2Agent protocol
- Periodic Vault tokens (24h period) scoped to `sts/token/<agent>`, stored in KV at `credentials/<agent>-vault-token`
- `<agent>-kv-vault-token-read` policy added to the `test-client` Kubernetes auth role so VSO can read the token from KV

**Common Issues:**

1. **State mismatch after Vault reinitialization**
   - **Symptom**: `No secret engine mount at sts/`
   - **Cause**: Terraform state references resources from previous Vault instance
   - **Resolution**: Destroy vault workspace state and redeploy fresh

2. **Token role naming mismatch**
   - **Symptom**: VSO static secret sync fails with `permission denied` on `credentials/data/test-client-vault-token`
   - **Cause**: `kv_vault_token_read` policy not attached to the `test-client` Kubernetes auth role
   - **Resolution**: Verify `vault_kubernetes_auth_backend_role.client_agents` includes `vault_policy.kv_vault_token_read`

### 5. Deploy Helloworld Workspace

**Automated Steps:**

```bash
# Create run via Terraform MCP server
# Use tool: create_run
# Parameters:
#   - terraform_org_name: "your-org-name"
#   - workspace_name: "helloworld"
#   - message: "Deploy helloworld agents - Approved with IBM Bob"

# Monitor and apply
bash scripts/check-run-status.sh <run-id> 30 20
```

**What gets deployed:**
- helloworld-agent-server deployment and service
- test-client deployment and service
- Vault Secrets Operator resources for dynamic and static secrets
- `VaultStaticSecret` CR (`test-client-vault-token`) syncing the pre-created periodic token from `credentials/test-client-vault-token` KV path; `refreshAfter: 86400s` matches the token's 24h period
- ConfigMaps for agent configuration
- Ingresses for external access

**Common Issues:**

1. **Terraform state corruption**
   - **Symptom**: `Unexpected Identity Change` error for `kubernetes_deployment_v1.test_client`
   - **Cause**: State has null identity values while actual resource has proper values
   - **Resolution**: Remove corrupted resource from state and retry

2. **VSO static secret sync failure**
   - **Symptom**: Deployment stuck waiting for `test-client-vault-token` secret
   - **Cause**: `kv_vault_token_read` policy not on the `test-client` Kubernetes auth role, or periodic token not created in vault workspace
   - **Resolution**: Redeploy vault workspace first, then helloworld workspace

## Helper Scripts

### check-run-status.sh

Monitors HCP Terraform run status via API.

**Usage:**
```bash
bash scripts/check-run-status.sh <run-id> <interval-seconds> <max-checks>
```

**Parameters:**
- `run-id`: HCP Terraform run ID (e.g., run-abc123)
- `interval-seconds`: Seconds between status checks (default: 30)
- `max-checks`: Maximum number of checks before timeout (default: 20)

**Exit Codes:**
- `0`: Run completed successfully
- `1`: Run failed or was canceled
- `2`: Intermediate state (used internally for looping)

**Example:**
```bash
# Monitor run with 30-second intervals, max 20 checks (10 minutes)
bash scripts/check-run-status.sh run-abc123 30 20
```

### vault-init.sh

Initializes Vault cluster and registers plugins.

**Usage:**
```bash
bash scripts/vault-init.sh
```

**Output:**
- Creates `secrets/vault-init.json` with root token and recovery keys
- Exports environment variables for Vault access
- Registers oauth token exchange plugin

## Terraform MCP Server Tools

### Key Tools Used

1. **create_run**: Creates a new Terraform run
2. **action_run**: Applies, discards, or cancels a run
3. **get_run_details**: Fetches run status and metadata
4. **get_plan_details**: Gets plan summary (additions, changes, destructions)
5. **get_plan_logs**: Retrieves detailed plan logs
6. **get_apply_logs**: Retrieves detailed apply logs
7. **list_runs**: Lists recent runs for a workspace

### Workflow Pattern

```
1. create_run → get run_id
2. Monitor with check-run-status.sh until "planned"
3. get_plan_details → review changes
4. action_run (apply) → approve and start apply
5. Monitor with check-run-status.sh until "applied"
```

## Troubleshooting

### AWS Credentials

Ensure AWS credentials are properly configured:

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Configure kubectl with AWS credentials
aws eks update-kubeconfig --region <region> --name <cluster-name>
```

### Vault Access

**Never print root token:**
- ❌ `jq -r '.root_token' secrets/vault-init.json`
- ✅ Use as environment variable: `export VAULT_TOKEN=$(jq -r '.root_token' secrets/vault-init.json)`

### State Management

**When to destroy and redeploy:**
1. TLS certificate issues (kubernetes workspace)
2. Vault reinitialization (vault workspace)
3. State corruption (any workspace)

**How to destroy:**
```bash
# Via Terraform MCP server
# Use tool: create_run with is_destroy: true
# Then action_run with run_action: "apply"
```

## Verification

After successful deployment:

```bash
# Check Vault pods
kubectl get pods -n vault

# Check agent deployments
kubectl get deployments -n default

# Get test-client URL
cd terraform/kubernetes && terraform output -raw test_client_url

# Get helloworld-server URL
cd terraform/kubernetes && terraform output -raw helloworld_agent_server_url
```

## Next Steps

After deployment, test the Agent2Agent protocol:
1. Open test-client UI
2. Login with end-user credentials
3. Request subject token with may-act claim
4. Exchange for delegated access token
5. Call helloworld-server with access token