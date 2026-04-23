tfc_organization = "rosemary-production"

client_agents = {
  "test-client" = {
    "k8s_namespace" = "default",
    "claims" = {
      "scope" : "helloworld:read"
    }

  }
  "second-client" = {
    "k8s_namespace" = "default",
    "claims" = {
      "scope" : "helloworld:write"
    }

  }
}