# Helloworld Agent Terraform Configuration

This Terraform configuration deploys the helloworld agent server to Kubernetes.

## Overview

This configuration creates:
- Kubernetes Service (ClusterIP) for the helloworld agent server
- Kubernetes Deployment with the helloworld agent container

The configuration automatically fetches the latest Docker image from ECR using the base workspace outputs.

## Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate credentials
- Access to the base Terraform workspace (for remote state)
- EKS cluster already provisioned (via base workspace)

## Usage

1. Update `terraform.auto.tfvars` with your Terraform Cloud organization:
   ```hcl
   tfc_organization = "your-tfc-org"
   ```

2. Initialize Terraform:
   ```bash
   terraform init
   ```

3. Review the plan:
   ```bash
   terraform plan
   ```

4. Apply the configuration:
   ```bash
   terraform apply
   ```

## Configuration

### Required Variables

- `tfc_organization` - Your Terraform Cloud organization name

### Optional Variables

All other variables have sensible defaults but can be overridden:

- `aws_region` - AWS region (default: "us-east-1")
- `environment` - Environment name (default: "dev")
- `project_name` - Project name (default: "infrastructure-agent")
- `app_name` - Application name (default: "helloworld-agent-server")
- `app_replicas` - Number of replicas (default: 1)
- `app_port` - Application port (default: 9999)
- `openid_connect_url` - OpenID Connect URL for authentication
- `agent_url` - Agent URL (default: "")
- `vault_skip_verify` - Skip TLS verification for Vault (default: "true")
- `memory_request` - Memory request (default: "128Mi")
- `memory_limit` - Memory limit (default: "512Mi")
- `cpu_request` - CPU request (default: "100m")
- `cpu_limit` - CPU limit (default: "500m")

## Resources Created

- `kubernetes_service_v1.helloworld_agent_server` - ClusterIP service
- `kubernetes_deployment_v1.helloworld_agent_server` - Deployment with 1 replica

## Dependencies

This configuration depends on:
- `terraform/base` workspace for:
  - EKS cluster configuration
  - ECR repository URL and name
  - Cluster endpoint and authentication

## Notes

- The Docker image is automatically pulled from ECR using the latest tag
- The deployment includes health checks (liveness and readiness probes)
- Security context is configured with non-root user and dropped capabilities
- Resource limits are set to prevent resource exhaustion