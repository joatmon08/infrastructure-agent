# Example repository for infrastructure-agent

This example repository includes demo code for:

- Agents using [Agent2Agent protocol](https://a2a-protocol.org/latest/) and [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/secrets/identity/oidc-provider) as an OIDC provider on Kubernetes
- [LangFlow](https://www.langflow.org/), OpenSearch, Ollama (with Granite 4) deployed on AWS EKS

## Prerequisites

- AWS account
- [HCP Terraform](https://developer.hashicorp.com/terraform/cloud-docs)
- Docker (for pushing images)

### Set up HCP Terraform

Log into the HCP Terraform.

- Create a new project called `infrastructure-agent`. It groups the workspaces related to this repository.

Configure the workspace for base infrastructure.

- Create a workspace called `base`.

- Set the project to `infrastructure-agent`.

- Go to "Settings".

- Scroll down to "Remote state sharing".

- Select "Share with all workspaces in this project".

- Go to "Version Control".

- Connect the workspace to this repository (`joatmon08/infrastructure-agent`).

- Update "Terraform Working Directory" to `terraform/base`.

- Under "Automatic Run triggering", set to "Only trigger when files in specified paths change".

- Update the "Syntax" to "Patterns".

- Add the pattern `terraform/base/**/*`.

Go back to the list of workspaces.

- Go to "Settings".

- Go to "Variable Sets".

- Create an organization variable set.

- Apply to the `base` workspace (or the project that will contain the rest of the workspaces).

- Add the following variables:
    - `aws_region`
    - `environment`
    - `inbound_cidrs_for_lbs`
    - `project_name`
    - AWS credentials (preferred using environment variables)

### Deploy base infrastructure

- Go to the `base` workspace.

- Select "New run".

This will show a run that creates a EKS cluster in
[auto-mode](https://docs.aws.amazon.com/eks/latest/userguide/automode.html),
ECR repositories for various images, a Vault cluster on the Kubernetes cluster with
[auto-unseal using AWS KMS](https://developer.hashicorp.com/vault/tutorials/auto-unseal/autounseal-aws-kms).
It also deploys the `StorageClass` for EBS volumes to be managed by auto-mode.

- After the infrastructure finishes running, log into the Kubernetes cluster.
    ```bash
    aws eks update-kubeconfig --region us-east-1 --name infra-agent
    ```

- Initialize Vault. Save the output of the command to a file, as you will need the Vault root token
to further configure Vault.
    ```bash
    kubectl exec -it vault-0 -n vault -- vault operator init > secrets.txt
    ```

## Agent2Agent with Vault as OIDC provider

This demo deploys two example agents, `helloworld-agent` and `test-client`.
Each of them use [Agent2Agent protocol](https://a2a-protocol.org/latest/) for agent
discovery and communication. The extended agent skills in `helloworld-agent` require proper authentication
and authorization by Vault in order for other agents to access.

### Set up HCP Terraform

Log into HCP Terraform.

- Create a workspace called `kubernetes`.

- Set the project to `infrastructure-agent`.

- Go to "Settings".

- Scroll down to "Remote state sharing".

- Select "Share with all workspaces in this project".

- Go to "Version Control".

- Connect the workspace to this repository (`joatmon08/infrastructure-agent`).

- Update "Terraform Working Directory" to `terraform/kubernetes`.

- Under "Automatic Run triggering", set to "Only trigger when files in specified paths change".

- Update the "Syntax" to "Patterns".

- Add the pattern `terraform/kubernetes/**/*`.

Now set up the variables.

- Go to the `kubernetes` workspace.

- Go to "Variables".

- Add the following workspace variables:
    - `vault_token` (sensitive) - The Vault root token from the initialization step
    - `inbound_cidrs_for_lbs` (HCL) - List of CIDR blocks allowed to access load balancers (can override with `["0.0.0.0/0"]`)

The workspace will also use the organization variable set created for the `base` workspace.

### Configure Vault and Kubernetes

- Go to the `kubernetes` workspace.

- Select "New run".

This will deploy the Kubernetes resources for the agents, including Vault OIDC configuration,
Kubernetes service accounts, and the necessary Vault policies.

After the run completes, you can retrieve the end-user credentials from the workspace outputs:

```bash
terraform output end_user_username
terraform output end_user_password
```

These credentials are used to authenticate with Vault's OIDC provider when accessing the agent services.
The configuration creates:

- **end-user** - A Vault userpass authentication user that is allowed to access the Vault OIDC endpoints
- **test-client** - Vault authentication role that allows access to OIDC endpoints for the test-client Kubernetes service account

The configuration also creates services on Kubernetes for `test-client` and `helloworld-agent-server`.

- **helloworld-agent-server** - Uses a Kubernetes ingress with AWS ALB for access
- **test-client** - Uses a Kubernetes service with AWS NLB for access

### Deploy agents

You need to build and push images to the ECR repositories created in your AWS account.

- Run `build-helloworld.sh` to automatically build and push to the account ECR repositories.

    ```bash
    bash build-helloworld.sh
    ```

Next, set up HCP Terraform to deploy the agents. Log into the HCP Terraform.

- Create a workspace called `helloworld`.

- Set the project to `infrastructure-agent`.

- Go to "Settings".

- Go to "Version Control".

- Connect the workspace to this repository (`joatmon08/infrastructure-agent`).

- Update "Terraform Working Directory" to `terraform/helloworld`.

- Under "Automatic Run triggering", set to "Only trigger when files in specified paths change".

- Update the "Syntax" to "Patterns".

- Add the pattern `terraform/helloworld/**/*`.

Set up the variables.

- Go to the `helloworld` workspace.

- Go to "Variables".

- Add the following workspace variable:
    - `tfc_organization` - Your Terraform Cloud organization name (e.g., `rosemary-production`)

The workspace will also use the organization variable set created for the `base` workspace.

Note: Most variables have defaults in `terraform.auto.tfvars` and can be overridden if needed.

### Deploy agent infrastructure

- Go to the `helloworld` workspace.

- Select "New run".

This will deploy the Kubernetes deployment and service for the helloworld-agent-server.
The agent will be accessible via the ingress created in the `kubernetes` workspace.

After the run completes, you can access the test-client at the URL from the `kubernetes` workspace outputs:

```bash
terraform output test_client_url
```

Use the end-user credentials retrieved earlier to authenticate with the agent.

### Try the agents

After deploying the components for this demo, you can access the test-client agent UI at:

```bash
open $(cd terraform/kubernetes && terraform output -raw test_client_url)
```

This opens an A2A client with a UI.

![Test Client Home](assets/test-client-home.png)

Define the scopes you want the agent to use to
connect to `helloworld-agent-server`.

Use the "Login" button, which redirects you
to Vault as an OIDC provider.

Log into Vault using the `end-user` username and password.

```shell
cd terraform/kubernetes && terraform output -raw end_user_username
cd terraform/kubernetes && terraform output -raw end_user_password
```

If your client agent does not define the proper scopes and sends
a request to the `helloworld-agent-server`, your agent gets a 403 FORBIDDEN for accessing helloworld skills.

![Test Client 403 Forbidden](assets/test-client-403.png)

If your client agent defines the correct scope (`helloworld-read`)
and sends a request to `helloworld-agent-server`, your agent gets a 200 SUCCESS
with a "Hello World" message.

![Test Client 200 Success](assets/test-client-200.png)

## LangFlow

Update `langflow-build.sh` to the correct ECR repository.

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