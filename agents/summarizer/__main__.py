import logging
import os

import uvicorn

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    HTTPAuthSecurityScheme,
    OpenIdConnectSecurityScheme,
    SecurityScheme,
)
from agent_executor import SummarizerAgentExecutor  # type: ignore[import-untyped]
from auth_middleware import AuthMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_URL = os.getenv("AGENT_URL", "http://localhost:9999")
OPENID_CONNECT_URL = os.getenv("OPENID_CONNECT_URL")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"

if __name__ == "__main__":
    security_schemes = {
        "bearer": SecurityScheme(
            root=HTTPAuthSecurityScheme(
                type="http",
                scheme="bearer",
                bearer_format="JWT",
                description="OAuth 2.0 access token with 'summarizer:summarize' scope",
            )
        )
    }
    security = [{"bearer": ["summarizer:summarize"]}]

    if OPENID_CONNECT_URL:
        security_schemes["oauth"] = SecurityScheme(
            root=OpenIdConnectSecurityScheme(
                description="Vault OIDC provider",
                type="openIdConnect",
                open_id_connect_url=OPENID_CONNECT_URL,
            )
        )
        security.append({"oauth": ["summarizer:summarize"]})

    skill = AgentSkill(
        id="summarize_text",
        name="Summarize Text",
        description="Returns a one-sentence summary of any input text using Ollama.",
        tags=["summarize", "text", "llm"],
        examples=["Summarize this article: ...", "Give me a one-sentence summary of ..."],
    )

    public_agent_card = AgentCard(
        name="summarizer-agent",
        description="Summarizes any text into one sentence using Ollama (llama3.2:3b).",
        url=AGENT_URL,
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
        supports_authenticated_extended_card=True,
        security_schemes=security_schemes,
        security=security,
    )

    request_handler = DefaultRequestHandler(
        agent_executor=SummarizerAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    server = A2AStarletteApplication(
        agent_card=public_agent_card,
        http_handler=request_handler,
    )

    app = server.build()

    if not OPENID_CONNECT_URL:
        raise ValueError("OPENID_CONNECT_URL environment variable must be set")

    app.add_middleware(
        AuthMiddleware,
        agent_card=public_agent_card,
        public_paths=["/.well-known/agent-card.json"],
        openid_connect_url=OPENID_CONNECT_URL,
        verify_tls=VERIFY_TLS,
    )

    uvicorn.run(app, host="0.0.0.0", port=9999)
