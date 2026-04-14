# Vault Custom Plugin Setup Guide

This guide explains how to configure and deploy custom secrets engine plugins for your Vault cluster running on Kubernetes.

## Architecture Overview

The solution uses **Amazon EFS (Elastic File System)** to provide shared storage for Vault plugins across all Vault server replicas. This is necessary because:

- Your Vault cluster runs with **3 replicas** in HA mode
- All Vault servers need **simultaneous read access** to the same plugin binaries
- EFS supports `ReadWriteMany` access mode, allowing multiple pods to mount the same volume
- EBS only supports `ReadWriteOnce`, which would limit access to a single pod

### Components

1. **EFS File System** (`vault-plugin-storage.tf`)
   - Encrypted storage using KMS
   - Mount targets in each availability zone
   - Security group allowing NFS traffic from VPC

2. **Kubernetes Storage** (`vault-plugin-storage.tf`)
   - EFS CSI Driver StorageClass
   - PersistentVolumeClaim for plugin storage
   - Mounted at `/vault/plugins` in each Vault pod

3. **Plugin Loader** (`vault-plugin-loader.tf`)
   - Kubernetes Job that downloads plugins
   - Uses official HashiCorp Vault image (secure and maintained)
   - Runs with Vault service account for IRSA permissions

4. **Vault Configuration** (`templates/vault.yaml.tpl`)
   - `plugin_directory = "/vault/plugins"` in Vault config
   - Volume mount for the EFS-backed PVC

## Prerequisites

Before deploying plugins, ensure:

1. **EFS CSI Driver** is installed in your EKS cluster:
   ```bash
   kubectl get csidriver efs.csi.aws.com
   ```

2. **Vault IAM Role** has EFS permissions (automatically configured via Terraform)

3. **Network connectivity** between EKS nodes and EFS mount targets

## Configuration

### Step 1: Define Your Plugins

Edit `terraform/base/terraform.auto.tfvars` and add your plugin configuration:

```hcl
vault_plugins = [
  {
    name   = "vault-plugin-secrets-custom"
    url    = "https://github.com/your-org/vault-plugin-secrets-custom/releases/download/v1.0.0/vault-plugin-secrets-custom-linux-amd64"
    sha256 = "abc123def456..." # SHA256 checksum of the plugin binary
  },
  {
    name   = "vault-plugin-auth-custom"
    url    = "https://releases.example.com/vault-plugin-auth-custom-v2.0.0"
    sha256 = "789ghi012jkl..."
  }
]
```

**Important Notes:**
- `name`: The filename for the plugin in `/vault/plugins/`
- `url`: Direct download URL for the plugin binary
- `sha256`: SHA256 checksum for verification (highly recommended for security)

### Step 2: Apply Terraform Configuration

```bash
cd terraform/base
terraform init
terraform plan
terraform apply
```

This will:
1. Create the EFS file system and mount targets
2. Create the Kubernetes StorageClass and PVC
3. Update Vault configuration to use the plugin directory
4. Run the plugin loader job to download plugins
5. Restart Vault pods to mount the plugin volume

### Step 3: Verify Plugin Installation

Check that the plugin loader job completed successfully:

```bash
kubectl get jobs -n vault -l component=plugin-loader
kubectl logs -n vault job/vault-plugin-loader-<timestamp>
```

Verify plugins are accessible from Vault pods:

```bash
kubectl exec -n vault vault-0 -- ls -lh /vault/plugins
```

### Step 4: Register Plugins in Vault

Once plugins are loaded, register them with Vault:

```bash
# Get the SHA256 sum of the plugin
PLUGIN_SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-custom | cut -d' ' -f1)

# Register the plugin
vault plugin register \
  -sha256="${PLUGIN_SHA256}" \
  -command="vault-plugin-secrets-custom" \
  secret \
  vault-plugin-secrets-custom

# Enable the secrets engine
vault secrets enable -path=custom vault-plugin-secrets-custom
```

## Plugin Updates

To update plugins:

1. Update the `vault_plugins` variable in `terraform.auto.tfvars` with new URLs/checksums
2. Run `terraform apply`
3. The plugin loader job will automatically run with a new timestamp
4. Re-register the plugin in Vault with the new SHA256

```bash
# Reload the plugin in Vault
vault plugin reload -plugin vault-plugin-secrets-custom
```

## Security Considerations

### Plugin Binary Security

- **Always verify SHA256 checksums** to ensure plugin integrity
- Download plugins from **trusted sources only**
- Use **HTTPS URLs** for plugin downloads
- Consider hosting plugins in a **private S3 bucket** with IAM authentication

### Access Control

- Plugin loader job runs with **Vault service account** (IRSA enabled)
- EFS is **encrypted at rest** using KMS
- EFS security group restricts access to **VPC CIDR only**
- Plugins are mounted **read-only** in Vault pods

### Network Security

- EFS mount targets are in **private subnets only**
- NFS traffic (port 2049) is restricted to VPC CIDR
- No public access to EFS file system

## Troubleshooting

### Plugin Loader Job Fails

Check job logs:
```bash
kubectl logs -n vault -l component=plugin-loader
```

Common issues:
- **Network connectivity**: Ensure EKS nodes can reach plugin download URLs
- **Invalid URL**: Verify the plugin URL is accessible
- **Checksum mismatch**: Ensure SHA256 matches the actual binary
- **Permissions**: Check that the job can write to EFS

### Vault Cannot Find Plugin

Verify plugin is in the directory:
```bash
kubectl exec -n vault vault-0 -- ls -lh /vault/plugins
```

Check Vault logs:
```bash
kubectl logs -n vault vault-0
```

Ensure plugin is executable:
```bash
kubectl exec -n vault vault-0 -- stat /vault/plugins/vault-plugin-secrets-custom
```

### EFS Mount Issues

Check EFS mount targets:
```bash
aws efs describe-mount-targets --file-system-id <efs-id>
```

Verify security group rules:
```bash
aws ec2 describe-security-groups --group-ids <sg-id>
```

Check CSI driver pods:
```bash
kubectl get pods -n kube-system -l app=efs-csi-controller
kubectl get pods -n kube-system -l app=efs-csi-node
```

## Cost Optimization

EFS costs are based on:
- **Storage used**: Pay only for what you store
- **Throughput**: Bursting mode is included
- **Lifecycle management**: Files transition to IA (Infrequent Access) after 30 days

For plugin storage (typically < 1GB), monthly costs are minimal (~$0.30/GB/month).

## Alternative Approaches

If you prefer not to use EFS, consider:

1. **Init Container with S3**: Download plugins to each pod's local storage on startup
2. **ConfigMap**: For small plugins (< 1MB), store directly in ConfigMap
3. **Custom Container Image**: Bake plugins into a custom Vault image

However, EFS provides the best balance of:
- Shared access across all replicas
- Easy updates without pod restarts
- Separation of plugin management from Vault deployment

## References

- [Vault Plugin System](https://developer.hashicorp.com/vault/docs/plugins)
- [Vault Plugin Development](https://developer.hashicorp.com/vault/docs/plugins/plugin-development)
- [EFS CSI Driver](https://github.com/kubernetes-sigs/aws-efs-csi-driver)
- [Vault on Kubernetes](https://developer.hashicorp.com/vault/docs/platform/k8s)