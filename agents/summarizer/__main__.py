import logging
import os

import uvicorn

from starlette.applications import Starlette
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    HTTPAuthSecurityScheme,
    OpenIdConnectSecurityScheme,
    SecurityScheme,
)
from agent_executor import SummarizerAgent, SummarizerAgentExecutor  # type: ignore[import-untyped]
import auth_middleware
from auth_middleware import AuthMiddleware, OpenIDConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_URL = os.getenv("AGENT_URL", "http://localhost:9999")
AGENT_HOST = os.getenv("AGENT_HOST", "127.0.0.1")
AGENT_PORT = int(os.getenv("AGENT_PORT", "9999"))
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() == "true"
OPENID_CONNECT_URL = os.getenv("OPENID_CONNECT_URL")
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"


def build_agent_card() -> AgentCard:
    security_schemes = None
    security_requirements = None

    if AUTH_ENABLED:
        security_schemes = {
            "bearer": SecurityScheme(
                http_auth_security_scheme=HTTPAuthSecurityScheme(
                    scheme="bearer",
                    bearer_format="JWT",
                    description="OAuth 2.0 access token with 'summarizer:summarize' scope",
                )
            )
        }
        security_requirements = [
            {"schemes": {"bearer": {"list": ["summarizer:summarize"]}}}
        ]

        if OPENID_CONNECT_URL:
            security_schemes["oauth"] = SecurityScheme(
                open_id_connect_security_scheme=OpenIdConnectSecurityScheme(
                    description="Vault OIDC provider",
                    open_id_connect_url=OPENID_CONNECT_URL,
                )
            )
            security_requirements.append(
                {"schemes": {"oauth": {"list": ["summarizer:summarize"]}}}
            )

    skill = AgentSkill(
        id="summarize_text",
        name="Summarize Text",
        description="Returns a one-sentence summary of any input text using Ollama.",
        tags=["summarize", "text", "llm"],
        examples=["Summarize this article: ...", "Give me a one-sentence summary of ..."],
    )

    return AgentCard(
        name="summarizer-agent",
        description="Summarizes any text into one sentence using Ollama (llama3.2:3b).",
        supported_interfaces=[
            AgentInterface(
                url=AGENT_URL,
                protocol_binding="jsonrpc",
            )
        ],
        provider=AgentProvider(url=AGENT_URL),
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
        security_schemes=security_schemes,
        security_requirements=security_requirements,
    )


def build_app() -> Starlette:
    if AUTH_ENABLED and not OPENID_CONNECT_URL:
        raise ValueError("OPENID_CONNECT_URL environment variable must be set when AUTH_ENABLED=true")

    public_agent_card = build_agent_card()
    request_handler = DefaultRequestHandler(
        agent_executor=SummarizerAgentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=public_agent_card,
    )

    app = Starlette(
        routes=[
            *create_agent_card_routes(public_agent_card),
            *create_jsonrpc_routes(request_handler, "/"),
        ]
    )
    if AUTH_ENABLED:
        app.add_middleware(
            AuthMiddleware,
            agent_card=public_agent_card,
            public_paths=["/.well-known/agent-card.json"],
            openid_connect_url=OPENID_CONNECT_URL,
            verify_tls=VERIFY_TLS,
        )
    return app


def main() -> None:
    uvicorn.run(build_app(), host=AGENT_HOST, port=AGENT_PORT)


if __name__ == "__main__":
    main()
