# AWS Infrastructure with Terraform

This Terraform configuration creates a complete AWS infrastructure including:
- VPC with public and private subnets across multiple availability zones
- NAT Gateway for private subnet internet access
- EKS (Elastic Kubernetes Service) cluster with managed node groups

## Architecture

The infrastructure includes:

### VPC Module
- **VPC**: Custom VPC with configurable CIDR block
- **Subnets**: Public and private subnets across 3 availability zones
- **Internet Gateway**: For public subnet internet access
- **NAT Gateway**: For private subnet outbound internet access
- **Route Tables**: Separate routing for public and private subnets

### EKS Module
- **EKS Cluster**: Managed Kubernetes control plane
- **Managed Node Groups**: Auto-scaling worker nodes
- **Cluster Addons**: CoreDNS, kube-proxy, and VPC CNI
- **IAM Roles**: Automatically configured for cluster and nodes

## Prerequisites

1. **AWS CLI** installed and configured with appropriate credentials
   ```bash
   aws configure
   ```

2. **Terraform** installed (version >= 1.0)
   ```bash
   terraform version
   ```

3. **kubectl** installed for Kubernetes cluster management
   ```bash
   kubectl version --client
   ```

4. **AWS IAM Permissions**: Your AWS credentials need permissions to create:
   - VPC, Subnets, Route Tables, Internet Gateway, NAT Gateway
   - EKS Clusters, Node Groups
   - IAM Roles and Policies
   - Security Groups
   - EC2 Instances

## Quick Start

### 1. Configure Variables

Copy the example variables file and customize it:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your desired configuration:

```hcl
aws_region   = "us-east-1"
environment  = "dev"
project_name = "infrastructure-agent"
cluster_name = "my-eks-cluster"
```

### 2. Initialize Terraform

Initialize the Terraform working directory and download required providers:

```bash
terraform init
```

### 3. Review the Plan

Preview the infrastructure changes:

```bash
terraform plan
```

### 4. Apply the Configuration

Create the infrastructure:

```bash
terraform apply
```

Type `yes` when prompted to confirm.

**Note**: This process takes approximately 15-20 minutes as EKS cluster creation is time-intensive.

### 5. Configure kubectl

After successful deployment, configure kubectl to access your cluster:

```bash
aws eks update-kubeconfig --region <your-region> --name <your-cluster-name>
```

Or use the output command:

```bash
terraform output -raw configure_kubectl | bash
```

### 6. Verify Cluster Access

Test your connection to the cluster:

```bash
kubectl get nodes
kubectl get pods -A
```

## Configuration Variables

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for resources | `us-east-1` |
| `environment` | Environment name (dev/staging/prod) | `dev` |
| `project_name` | Project name for tagging | `infrastructure-agent` |

### VPC Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `vpc_cidr` | CIDR block for VPC | `10.0.0.0/16` |
| `availability_zones` | List of AZs to use | `["us-east-1a", "us-east-1b", "us-east-1c"]` |
| `private_subnet_cidrs` | CIDR blocks for private subnets | `["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]` |
| `public_subnet_cidrs` | CIDR blocks for public subnets | `["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]` |
| `enable_nat_gateway` | Enable NAT Gateway | `true` |
| `single_nat_gateway` | Use single NAT Gateway (cost optimization) | `true` |

### EKS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `cluster_name` | Name of the EKS cluster | `infrastructure-agent-cluster` |
| `cluster_version` | Kubernetes version | `1.28` |
| `node_group_desired_size` | Desired number of nodes | `2` |
| `node_group_min_size` | Minimum number of nodes | `1` |
| `node_group_max_size` | Maximum number of nodes | `4` |
| `node_instance_types` | EC2 instance types for nodes | `["t3.medium"]` |
| `node_disk_size` | Disk size in GB for nodes | `20` |

## Outputs

After applying, Terraform provides useful outputs:

```bash
# View all outputs
terraform output

# View specific output
terraform output cluster_endpoint
terraform output vpc_id
```

Key outputs include:
- `cluster_endpoint`: EKS cluster API endpoint
- `cluster_name`: Name of the EKS cluster
- `vpc_id`: ID of the created VPC
- `configure_kubectl`: Command to configure kubectl

## Cost Considerations

This infrastructure incurs AWS costs:

- **EKS Cluster**: ~$0.10/hour (~$73/month)
- **EC2 Instances** (t3.medium): ~$0.0416/hour per instance
- **NAT Gateway**: ~$0.045/hour + data transfer costs
- **Data Transfer**: Variable based on usage

**Estimated Monthly Cost**: ~$150-200 for the default configuration

### Cost Optimization Tips

1. **Single NAT Gateway**: Set `single_nat_gateway = true` (default)
2. **Smaller Instances**: Use `t3.small` instead of `t3.medium`
3. **Fewer Nodes**: Reduce `node_group_desired_size`
4. **Spot Instances**: Modify node group to use SPOT capacity

## Cleanup

To destroy all created resources:

```bash
terraform destroy
```

Type `yes` when prompted to confirm.

**Warning**: This will permanently delete all resources including the EKS cluster and VPC.

## Modules Used

This configuration uses official AWS Terraform modules:

- [terraform-aws-modules/vpc/aws](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws) (~> 5.0)
- [terraform-aws-modules/eks/aws](https://registry.terraform.io/modules/terraform-aws-modules/eks/aws) (~> 20.0)

## Troubleshooting

### Issue: Insufficient IAM Permissions

**Error**: `Error creating EKS Cluster: AccessDeniedException`

**Solution**: Ensure your AWS credentials have the necessary IAM permissions.

### Issue: Availability Zone Capacity

**Error**: `InsufficientInstanceCapacity`

**Solution**: Try different availability zones or instance types in `terraform.tfvars`.

### Issue: kubectl Connection Refused

**Error**: `The connection to the server localhost:8080 was refused`

**Solution**: Run the configure kubectl command from the outputs:
```bash
terraform output -raw configure_kubectl | bash
```

### Issue: Nodes Not Joining Cluster

**Solution**: Check security groups and ensure private subnets have NAT Gateway access.

## Security Best Practices

1. **State File**: Store Terraform state in S3 with encryption and versioning
2. **Secrets**: Never commit `terraform.tfvars` with sensitive data to version control
3. **IAM Roles**: Use least privilege principle for IAM roles
4. **Network**: Keep worker nodes in private subnets
5. **Updates**: Regularly update Kubernetes version and node AMIs

## Additional Resources

- [AWS EKS Documentation](https://docs.aws.amazon.com/eks/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Kubernetes Documentation](https://kubernetes.io/docs/)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review AWS CloudWatch logs
3. Consult AWS EKS documentation