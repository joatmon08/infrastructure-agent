# summarizer-agent

A2A agent that returns a one-sentence summary of any input text, powered by [Ollama](https://ollama.com) (`llama3.2:3b`) and protected by [HashiCorp Vault](https://developer.hashicorp.com/vault) OIDC JWT authentication.

## How it works

1. Caller sends a task to the agent via the A2A protocol
2. `AuthMiddleware` validates the inbound JWT against Vault's JWKS endpoint and checks for the `summarizer:summarize` scope
3. The agent calls Ollama at `OLLAMA_URL` with the prompt: *"Summarize the following text in one sentence:"*
4. The one-sentence summary is returned as an A2A text message

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `AGENT_URL` | `http://localhost:9999` | Public URL of this agent (used in the agent card) |
| `OPENID_CONNECT_URL` | *(required)* | Vault STS OIDC discovery URL for JWT validation |
| `OLLAMA_URL` | `http://ollama.ollama.svc.cluster.local:11434` | Ollama inference server endpoint |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model to use |
| `VERIFY_TLS` | `false` | Set to `true` to enforce TLS certificate verification |

## Running locally

```bash
# Start Ollama locally
ollama serve &
ollama pull llama3.2:3b

# Run the agent
AGENT_URL=http://localhost:9999 \
AGENT_HOST=127.0.0.1 \
OPENID_CONNECT_URL=https://<vault-addr>/v1/sts/.well-known/openid-configuration \
OLLAMA_URL=http://localhost:11434 \
uv run python __main__.py
```

The agent card is available at `GET http://localhost:9999/.well-known/agent-card.json`.

## Docker Compose

[`docker-compose.yaml`](agents/summarizer/docker-compose.yaml) starts both services needed for local end-to-end tests:

- `ollama` with the same model path and `llama3.2:3b` model used by [`terraform/summarizer/ollama.tf`](terraform/summarizer/ollama.tf:1)
- `summarizer`, built from [`Dockerfile`](agents/summarizer/Dockerfile), configured to call `http://ollama:11434`

```bash
podman-compose up --build
```

The compose file sets `AGENT_HOST=0.0.0.0` for the container explicitly, while the application default remains `127.0.0.1` outside containers.
