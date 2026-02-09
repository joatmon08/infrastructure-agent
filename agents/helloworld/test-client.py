import http
import logging
import os

from typing import Any
from uuid import uuid4

from anyio import TaskInfo
import httpx
from httpx_auth import OAuth2AuthorizationCode
import hvac

from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import (
    AgentCard,
    Message,
    Role,
    Part,
    TextPart
)

from a2a.utils.constants import (
    AGENT_CARD_WELL_KNOWN_PATH,
    EXTENDED_AGENT_CARD_PATH,
)

# Configure logging to show INFO level messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_SERVER_URL = os.getenv("AGENT_URL", "http://localhost:9999")

REDIRECT_URI_DOMAIN = os.getenv("REDIRECT_URI_DOMAIN", "localhost")
REDIRECT_URI_PORT = os.getenv("REDIRECT_URI_PORT", 9998)
REDIRECT_URI_ENDPOINT = os.getenv("REDIRECT_URI_ENDPOINT", "callback")

## Define these values for Vault as OIDC provider
TOKEN_ENDPOINT: str | None = os.getenv("TOKEN_ENDPOINT")
AUTHORIZATION_ENDPOINT: str | None = os.getenv("AUTH_ENDPOINT")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid")

## Define these values for Vault identity tokens
VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_ROLE = os.getenv("VAULT_ROLE", "default")


class OIDCAuthenticationConfig:
    def __init__(self):
        self.authorization_endpoint = AUTHORIZATION_ENDPOINT
        self.token_endpoint = TOKEN_ENDPOINT
        self.redirect_uri_domain = REDIRECT_URI_DOMAIN
        self.redirect_uri_port = REDIRECT_URI_PORT
        self.redirect_uri_endpoint = REDIRECT_URI_ENDPOINT
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.scope = OIDC_SCOPES


def authorization_code_flow(config):
    logger.info(
        f"Attempting to authenticate with OAuth2AuthorizationCode with scopes {config.scope}"
    )
    kwargs = dict(
        client_id=config.client_id,
        client_secret=config.client_secret,
        scope=config.scope,
    )

    auth = OAuth2AuthorizationCode(
        authorization_url=config.authorization_endpoint,
        token_url=config.token_endpoint,
        redirect_uri_domain=config.redirect_uri_domain,
        redirect_uri_port=config.redirect_uri_port,
        redirect_uri_endpoint=config.redirect_uri_endpoint,
        **kwargs,
    )
    return auth


async def get_token():
    logger.info(f"Attempting to get Vault identity token with {VAULT_ROLE}")
    vault_client = hvac.Client(
        url=VAULT_ADDR,
        token=VAULT_TOKEN,
        namespace=VAULT_NAMESPACE,
    )
    response = vault_client.secrets.identity.generate_signed_id_token(name=VAULT_ROLE)
    return response["data"]["token"]


class AgentAuth(httpx.Auth):
    """Custom httpx's authentication class to inject access token required by agent."""

    def __init__(self, agent_card: AgentCard, token):
        self.agent_card = agent_card
        self.token = token

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


async def main() -> None:
    # --8<-- [start:A2ACardResolver]

    base_url = AGENT_SERVER_URL

    async with httpx.AsyncClient(http2=True, timeout=60) as httpx_client:
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=base_url,
        )

        final_agent_card_to_use: AgentCard | None = None

        try:
            logger.info(
                f"Attempting to fetch public agent card from: {base_url}{AGENT_CARD_WELL_KNOWN_PATH}"
            )
            _public_card = (
                await resolver.get_agent_card()
            )  # Fetches from default public path
            logger.info("Successfully fetched public agent card:")
            logger.info(_public_card.model_dump_json(indent=2, exclude_none=True))
            final_agent_card_to_use = _public_card
            logger.info(
                "\nUsing PUBLIC agent card for client initialization (default)."
            )

            if _public_card.supports_authenticated_extended_card:
                if (
                    TOKEN_ENDPOINT
                    and AUTHORIZATION_ENDPOINT
                    and CLIENT_ID
                    and CLIENT_SECRET
                ):
                    httpx_client.auth = authorization_code_flow(
                        OIDCAuthenticationConfig()
                    )
                elif VAULT_ADDR and VAULT_NAMESPACE and VAULT_TOKEN:
                    token = await get_token()
                    httpx_client.headers["Authorization"] = f"Bearer {token}"
                else:
                    raise NotImplementedError(
                        "No authentication specified for authenticated extended card. Use OIDC or Vault identity token"
                    )

                try:
                    logger.info(
                        f"\nPublic card supports authenticated extended card. Attempting to fetch from: {base_url}{EXTENDED_AGENT_CARD_PATH}"
                    )

                    _extended_card = await resolver.get_agent_card(
                        relative_card_path=EXTENDED_AGENT_CARD_PATH,
                    )
                    logger.info(
                        "Successfully fetched authenticated extended agent card"
                    )
                    logger.info(
                        _extended_card.model_dump_json(indent=2, exclude_none=True)
                    )
                    final_agent_card_to_use = (
                        _extended_card  # Update to use the extended card
                    )
                    logger.info(
                        "Using AUTHENTICATED EXTENDED agent card for client initialization"
                    )
                except Exception as e_extended:
                    logger.warning(
                        f"Failed to fetch extended agent card: {e_extended}. Will proceed with public card",
                        exc_info=True,
                    )
            elif _public_card:  # supports_authenticated_extended_card is False or None
                logger.info(
                    "Public card does not indicate support for an extended card. Using public card"
                )

        except Exception as e:
            logger.error(f"Critical error fetching public agent card: {e}")
            raise RuntimeError()

        config = ClientConfig(
            streaming=True,
            httpx_client=httpx_client,
        )

        factory = ClientFactory(config=config)
        client = factory.create(final_agent_card_to_use)
        logger.info("A2AClient initialized")

        logger.info(httpx_client.auth)

        message = Message(
            message_id=str(uuid4()), 
            role=Role.user,
            parts=[Part(root=TextPart(text="Give me a hello world"))],
        )
        
        try:
            stream = client.send_message(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise RuntimeError()

        async for event in stream:
            if hasattr(event, 'parts'):
                if hasattr(event.parts[0], 'root'):
                    if hasattr(event.parts[0].root, 'text'):
                            print(event.parts[0].root.text)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
