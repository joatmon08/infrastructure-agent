# Hello World Example

This example returns message events. It is based on the [Hello World Example](https://github.com/a2aproject/a2a-samples/tree/main/samples/python/agents/helloworld)
from the A2A Samples repository.

## Prerequisites

1. Set up Vault using the `../terraform` directory.
   You need to have the [Vault OIDC identity provider](https://developer.hashicorp.com/vault/docs/secrets/identity/oidc-provider)
   or [identity tokens](https://developer.hashicorp.com/vault/docs/secrets/identity/identity-token) configured.

1. Get the OIDC configuration information from Vault.
   ```sh
   $ curl -s -H "X-Vault-Token:${VAULT_TOKEN}" -H "X-Vault-Namespace:${VAULT_NAMESPACE}" $VAULT_ADDR/v1/identity/oidc/provider/agent/.well-known/openid-configuration | jq .
    {
        "issuer": "$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent",
        "jwks_uri": "$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent/.well-known/keys",
        "authorization_endpoint": "$VAULT_ADDR/ui/vault/$VAULT_NAMESPACE/identity/oidc/provider/agent/authorize",
        "token_endpoint": "$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent/token",
        "userinfo_endpoint": "$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent/userinfo",
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "EdDSA"
        ],
        "response_types_supported": [
            "code"
        ],
        "scopes_supported": [
            "groups",
            "helloworld",
            "user",
            "openid"
        ],
        "claims_supported": [],
        "subject_types_supported": [
            "public"
        ],
        "grant_types_supported": [
            "authorization_code"
        ],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_basic",
            "client_secret_post"
        ],
        "code_challenge_methods_supported": [
            "plain",
            "S256"
        ]
    }
   ```

## Starting the server

1. For Vault OIDC identity provider, define the following environment variables:
   ```sh
   export OPENID_CONNECT_URL=$VAULT_ADDR/v1/identity/oidc/provider/agent/.well-known/openid-configuration
   export USERINFO_ENDPOINT=$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent/userinfo
   ```

1. Start the server
   ```sh
   uv run .
   ```

## Starting the client

1. For Vault OIDC identity provider, define the following environment variables:
   ```sh
   export AUTH_ENDPOINT=$VAULT_ADDR/ui/vault/$VAULT_NAMESPACE/identity/oidc/provider/agent/authorize
   export TOKEN_ENDPOINT=$VAULT_ADDR/v1/$VAULT_NAMESPACE/identity/oidc/provider/agent/token

   export CLIENT_ID=$(vault read -field=client_id identity/oidc/client/agent)
   export CLIENT_SECRET=$(vault read -field=client_secret identity/oidc/client/agent)
   ```

1. Run the client
   ```sh
   uv run test_client.py
   ```