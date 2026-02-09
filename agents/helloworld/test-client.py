import logging
import os

from typing import Any
from uuid import uuid4

from fastapi.openapi.models import OAuthFlowAuthorizationCode
import httpx
from httpx_auth import OAuth2AuthorizationCode
import hvac

from a2a.client import A2ACardResolver, A2AClient
from a2a.types import (
    AgentCard,
    MessageSendParams,
    SendStreamingMessageRequest,
)

from a2a.utils.constants import (
    AGENT_CARD_WELL_KNOWN_PATH,
    EXTENDED_AGENT_CARD_PATH,
)

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc7523 import ClientSecretJWT

# Configure logging to show INFO level messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AGENT_SERVER_URL = os.getenv("AGENT_SERVER_URL", "http://localhost:9999")

REDIRECT_URI_DOMAIN = os.getenv("REDIRECT_URI_DOMAIN", "localhost")
REDIRECT_URI_PORT = os.getenv("REDIRECT_URI_PORT", 9998)
REDIRECT_URI_ENDPOINT = os.getenv("REDIRECT_URI_ENDPOINT", "callback")

## Define these values for Vault as OIDC provider
TOKEN_ENDPOINT: str | None = os.getenv("TOKEN_ENDPOINT")
AUTHORIZATION_ENDPOINT: str | None = os.getenv("AUTH_ENDPOINT")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

## Define these values for Vault identity tokens
VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


class OIDCAuthenticationConfig:
    def __init__(
        self,
        authorization_endpoint,
        token_endpoint,
        redirect_uri_domain,
        redirect_uri_port,
        redirect_uri_endpoint,
        client_id,
        client_secret,
        scope,
    ):
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.redirect_uri_domain = redirect_uri_domain
        self.redirect_uri_port = redirect_uri_port
        self.redirect_uri_endpoint = redirect_uri_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope


def authorization_code_flow(config):
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
    vault_client = hvac.Client(
        url=VAULT_ADDR,
        token=VAULT_TOKEN,
        namespace=VAULT_NAMESPACE,
    )
    response = vault_client.secrets.identity.generate_signed_id_token(
        name="helloworld-reader"
    )
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
    scopes = "openid helloworld"

    async with httpx.AsyncClient() as httpx_client:
        # Initialize A2ACardResolver
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=base_url,
            # agent_card_path uses default, extended_agent_card_path also uses default
        )
        # --8<-- [end:A2ACardResolver]

        # Fetch Public Agent Card and Initialize Client
        final_agent_card_to_use: AgentCard | None = None
        # token = await get_token()

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
                    config = OIDCAuthenticationConfig(
                        AUTHORIZATION_ENDPOINT,
                        TOKEN_ENDPOINT,
                        REDIRECT_URI_DOMAIN,
                        REDIRECT_URI_PORT,
                        REDIRECT_URI_ENDPOINT,
                        CLIENT_ID,
                        CLIENT_SECRET,
                        scopes,
                    )
                    httpx_client.auth = authorization_code_flow(config)
                elif VAULT_ADDR and VAULT_NAMESPACE and VAULT_TOKEN:
                    token = await get_token()
                    print(token)
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
                        "Successfully fetched authenticated extended agent card:"
                    )
                    logger.info(
                        _extended_card.model_dump_json(indent=2, exclude_none=True)
                    )
                    final_agent_card_to_use = (
                        _extended_card  # Update to use the extended card
                    )
                    logger.info(
                        "\nUsing AUTHENTICATED EXTENDED agent card for client initialization."
                    )
                except Exception as e_extended:
                    logger.warning(
                        f"Failed to fetch extended agent card: {e_extended}. Will proceed with public card.",
                        exc_info=True,
                    )
            elif _public_card:  # supports_authenticated_extended_card is False or None
                logger.info(
                    "\nPublic card does not indicate support for an extended card. Using public card."
                )

        except Exception as e:
            logger.error(f"Critical error fetching public agent card: {e}")
            raise RuntimeError()

        # --8<-- [start:send_message]
        client = A2AClient(
            httpx_client=httpx_client, agent_card=final_agent_card_to_use
        )
        logger.info("A2AClient initialized.")

        send_message_payload: dict[str, Any] = {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": "how much is 10 USD in INR?"}],
                "messageId": uuid4().hex,
            },
        }
        # --8<-- [start:send_message_streaming]
        streaming_request = SendStreamingMessageRequest(
            id=str(uuid4()), params=MessageSendParams(**send_message_payload)
        )

        stream_response = client.send_message_streaming(streaming_request)

        async for chunk in stream_response:
            print(chunk.model_dump(mode="json", exclude_none=True))


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
