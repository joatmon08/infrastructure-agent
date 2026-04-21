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
from agent_executor import (
    HelloWorldAgentExecutor,  # type: ignore[import-untyped]
)
from auth_middleware import AuthMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_URL = os.getenv("AGENT_URL", 'http://localhost:9999')

## Define the OIDC discovery URL for JWT validation
OPENID_CONNECT_URL = os.getenv("OPENID_CONNECT_URL")
## Optional: Disable TLS verification
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"

if __name__ == "__main__":
    security_schemes = {
        "bearer": SecurityScheme(
            root=HTTPAuthSecurityScheme(
                type="http",
                scheme="bearer",
                bearer_format="JWT",
                description="OAuth 2.0 access token with 'helloworld:read' scope",
            )
        )
    }
    security = [{"bearer": ["helloworld:read"]}]

    if OPENID_CONNECT_URL:
        security_schemes["oauth"] = SecurityScheme(
            root=OpenIdConnectSecurityScheme(
                description="OIDC provider",
                type="openIdConnect",
                open_id_connect_url=OPENID_CONNECT_URL,
            )
        )
        security.append({"oauth": ["helloworld:read"]})

    # --8<-- [start:AgentSkill]
    skill = AgentSkill(
        id="hello_world",
        name="Returns hello world",
        description="just returns hello world",
        tags=["hello world"],
        examples=["hi", "hello world"],
    )
    # --8<-- [end:AgentSkill]

    extended_skill = AgentSkill(
        id="super_hello_world",
        name="Returns a SUPER Hello World",
        description="A more enthusiastic greeting, only for authenticated users.",
        tags=["hello world", "super", "extended"],
        examples=["super hi", "give me a super hello"],
    )

    # --8<-- [start:AgentCard]
    # This will be the public-facing agent card
    public_agent_card = AgentCard(
        name="helloworld-server",
        description="Just a hello world agent",
        url=AGENT_URL,
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],  # Only the basic skill for the public card
        supports_authenticated_extended_card=True,
        security_schemes=security_schemes,
        security=security,
    )
    # --8<-- [end:AgentCard]

    # This will be the authenticated extended agent card
    # It includes the additional 'extended_skill'
    specific_extended_agent_card = public_agent_card.model_copy(
        update={
            "name": "Hello World Agent - Extended Edition",  # Different name for clarity
            "description": "The full-featured hello world agent for authenticated users.",
            "version": "1.0.1",  # Could even be a different version
            # Capabilities and other fields like url, default_input_modes, default_output_modes,
            # supports_authenticated_extended_card are inherited from public_agent_card unless specified here.
            "skills": [
                skill,
                extended_skill,
            ],  # Both skills for the extended card
        }
    )

    request_handler = DefaultRequestHandler(
        agent_executor=HelloWorldAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    server = A2AStarletteApplication(
        agent_card=public_agent_card,
        http_handler=request_handler,
        extended_agent_card=specific_extended_agent_card,
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
