# summarizer-agent

A2A agent that returns a one-sentence summary of any input text, powered by [Ollama](https://ollama.com) (`llama3.2:3b`). It supports both [HashiCorp Vault](https://developer.hashicorp.com/vault) OIDC JWT authentication and an unauthenticated mode for local integration.

## How it works

1. Caller sends a task to the agent via the A2A protocol
2. When `AUTH_ENABLED=true`, `AuthMiddleware` validates the inbound JWT against Vault's JWKS endpoint and checks for the `summarizer:summarize` scope
3. The agent calls Ollama at `OLLAMA_URL` with the prompt: *"Summarize the following text in one sentence:"*
4. The one-sentence summary is returned as an A2A task response

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `AGENT_URL` | `http://localhost:9999` | Public URL of this agent (used in the agent card) |
| `AUTH_ENABLED` | `true` | Set to `false` to disable JWT authentication entirely for local integration and testing |
| `OPENID_CONNECT_URL` | *(required when `AUTH_ENABLED=true`)* | Vault STS OIDC discovery URL for JWT validation |
| `OLLAMA_URL` | `http://ollama.ollama.svc.cluster.local:11434` | Ollama inference server endpoint |
| `OLLAMA_MODEL` | `llama3.2:3b` | Ollama model to use |
| `VERIFY_TLS` | `false` | Set to `true` to enforce TLS certificate verification |

## Running locally

### Auth enabled

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

### Auth disabled

```bash
# Start Ollama locally
ollama serve &
ollama pull llama3.2:3b

# Run the agent without JWT validation
AUTH_ENABLED=false \
AGENT_URL=http://localhost:9999 \
AGENT_HOST=127.0.0.1 \
OLLAMA_URL=http://localhost:11434 \
uv run python __main__.py
```

The agent card is available at `GET http://localhost:9999/.well-known/agent-card.json`.

## Tests

The smoke and request-flow tests live in [`agents/summarizer/tests/test_summarizer_app.py`](agents/summarizer/tests/test_summarizer_app.py:1).

They cover:

- agent-card startup and retrieval
- A2A request handling and summary return path
- auth-disabled startup
- auth-disabled agent-card security omission
- auth-enabled startup validation for `OPENID_CONNECT_URL`

Run them with:

```bash
uv run pytest tests/test_summarizer_app.py
```
