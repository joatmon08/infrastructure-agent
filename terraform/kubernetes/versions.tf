terraform {
  required_version = ">= 1.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.1"
    }
  }
}

data "terraform_remote_state" "base" {
  backend = "remote"

  config = {
    organization = var.tfc_organization
    workspaces = {
      name = var.tfc_base_workspace
    }
  }
}

provider "vault" {
  address         = data.terraform_remote_state.base.outputs.vault_endpoint
  token           = var.vault_token
  skip_tls_verify = true
}

provider "kubernetes" {
  host                   = data.terraform_remote_state.base.outputs.cluster_endpoint
  cluster_ca_certificate = base64decode(data.terraform_remote_state.base.outputs.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", data.terraform_remote_state.base.outputs.cluster_name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes = {
    host                   = data.terraform_remote_state.base.outputs.cluster_endpoint
    cluster_ca_certificate = base64decode(data.terraform_remote_state.base.outputs.cluster_certificate_authority_data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", data.terraform_remote_state.base.outputs.cluster_name]
      command     = "aws"
    }
  }
}