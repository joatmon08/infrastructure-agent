import asyncio
import logging
import os
import secrets
from typing import Optional
from urllib.parse import urlencode
from uuid import uuid4

from flask import Flask, render_template, jsonify, request, redirect, session, url_for
from flask_cors import CORS

import httpx
import hvac

from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import AgentCard, Message, Role, Part, TextPart

from a2a.utils.constants import (
    AGENT_CARD_WELL_KNOWN_PATH,
    EXTENDED_AGENT_CARD_PATH,
)

from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
CORS(app)

# Configuration from environment variables
AGENT_SERVER_URL = os.getenv("AGENT_URL", "http://localhost:9999")
APP_PORT = int(os.getenv("APP_PORT", 9000))

## Required to get client credentials or generate a signed token from Vault
VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_SKIP_VERIFY = os.getenv("VAULT_SKIP_VERIFY", "false").lower() == "true"

## Required for OIDC authentication
OPENID_CONNECT_PROVIDER_NAME = os.getenv("OPENID_CONNECT_PROVIDER_NAME")
OPENID_CONNECT_CLIENT_NAME = os.getenv("OPENID_CONNECT_CLIENT_NAME")

## Required for Vault identity tokens
VAULT_ROLE = os.getenv("VAULT_ROLE", "default")


class OIDCAuthenticationConfig:
    def __init__(self, vault_client, oidc_scopes=""):
        # Ensure "openid" scope is always included
        scopes = oidc_scopes.split() if oidc_scopes else []
        if "openid" not in scopes:
            scopes.append("openid")
        self.scope = " ".join(scopes)

        self.vault_client = vault_client
        self._get_openid_configuration()
        self._get_client_secret()

    def _get_openid_configuration(self):
        self.authorization_endpoint = None
        self.token_endpoint = None
        try:
            logger.info(
                f"Attempting to get Vault OIDC provider config for {OPENID_CONNECT_PROVIDER_NAME}"
            )
            response = self.vault_client.read(
                f"/identity/oidc/provider/{OPENID_CONNECT_PROVIDER_NAME}/.well-known/openid-configuration"
            )
            self.authorization_endpoint = f"{response["authorization_endpoint"]}"
            self.token_endpoint = response["token_endpoint"]
        except Exception as e:
            logger.error(
                f"Failed to get OIDC provider config for {OPENID_CONNECT_PROVIDER_NAME}: {str(e)}"
            )

    def _get_client_secret(self):
        self.client_id = None
        self.client_secret = None
        try:
            logger.info(
                f"Attempting to get client id and secret for {OPENID_CONNECT_CLIENT_NAME}"
            )
            response = self.vault_client.read(
                f"/identity/oidc/client/{OPENID_CONNECT_CLIENT_NAME}"
            )
            self.client_id = response["data"]["client_id"]
            self.client_secret = response["data"]["client_secret"]
        except Exception as e:
            logger.error(
                f"Failed to client id and secret for {OPENID_CONNECT_CLIENT_NAME}: {str(e)}"
            )


def get_oauth_auth_url(oidc_scopes: str = ""):
    """Generate OAuth2 authorization URL and return it."""
    try:
        # Build redirect URI from current request
        redirect_uri = url_for('oauth_callback',_external=True)
        
        # Initialize Vault client
        vault_client = hvac.Client(
            url=VAULT_ADDR,
            token=VAULT_TOKEN,
            verify=not VAULT_SKIP_VERIFY
        )
        
        # Get OIDC configuration
        config = OIDCAuthenticationConfig(vault_client, oidc_scopes)
        
        if not config.authorization_endpoint or not config.client_id:
            return None, "Failed to get OIDC configuration"
        
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        session["oauth_state"] = state
        session["oidc_scopes"] = oidc_scopes
        session["redirect_uri"] = redirect_uri
        
        # Store config in session for callback
        session["client_id"] = config.client_id
        session["client_secret"] = config.client_secret
        session["token_endpoint"] = config.token_endpoint
        
        # Build authorization URL
        params = {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": config.scope,
            "state": state,
        }
        
        auth_url = f"{config.authorization_endpoint}?{urlencode(params)}"
        logger.info(f"Generated authorization URL: {auth_url}")
        
        return auth_url, None
        
    except Exception as e:
        logger.error(f"Error generating OAuth URL: {str(e)}")
        return None, str(e)


async def exchange_code_for_token(client_id: str, client_secret: str, token_endpoint: str, code: str, redirect_uri: str) -> str:
    """Exchange authorization code for access token."""
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    
    async with httpx.AsyncClient(verify=not VAULT_SKIP_VERIFY) as client:
        response = await client.post(
            token_endpoint,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        response.raise_for_status()
        token_response = response.json()
        return token_response["access_token"]


async def get_token(vault_client):
    try:
        logger.info(f"Attempting to get Vault identity token with {VAULT_ROLE}")
        response = vault_client.secrets.identity.generate_signed_id_token(
            name=VAULT_ROLE
        )
        return response["data"]["token"]
    except Exception as e:
        logger.error(f"Failed to get Vault identity token: {str(e)}")
        raise e


async def send_agent_request(user_message: str, access_token: Optional[str] = None) -> dict:
    """Send a request to the agent and return the response."""
    base_url = AGENT_SERVER_URL
    response_text = []
    error_message = None

    try:
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
                _public_card = await resolver.get_agent_card()
                logger.info("Successfully fetched public agent card")
                final_agent_card_to_use = _public_card

                if _public_card.supports_authenticated_extended_card:
                    vault_client = hvac.Client(
                        url=VAULT_ADDR,
                        token=VAULT_TOKEN,
                        verify=not VAULT_SKIP_VERIFY
                    )

                    if OPENID_CONNECT_PROVIDER_NAME and OPENID_CONNECT_CLIENT_NAME:
                        # Use the access token from OAuth flow
                        if access_token:
                            httpx_client.headers["Authorization"] = f"Bearer {access_token}"
                        else:
                            error_message = "OAuth authentication required but no access token provided"
                            logger.error(error_message)
                            return {"success": False, "error": error_message, "requires_auth": True}
                    else:
                        token = await get_token(vault_client)
                        httpx_client.headers["Authorization"] = f"Bearer {token}"

                    try:
                        logger.info(
                            f"Attempting to fetch authenticated extended card from: {base_url}{EXTENDED_AGENT_CARD_PATH}"
                        )
                        _extended_card = await resolver.get_agent_card(
                            relative_card_path=EXTENDED_AGENT_CARD_PATH,
                        )
                        logger.info(
                            "Successfully fetched authenticated extended agent card"
                        )
                        final_agent_card_to_use = _extended_card
                    except Exception as e_extended:
                        logger.warning(
                            f"Failed to fetch extended agent card: {e_extended}. Will proceed with public card"
                        )

            except Exception as e:
                error_message = f"Critical error fetching public agent card: {str(e)}"
                logger.error(error_message)
                return {"success": False, "error": error_message}

            config = ClientConfig(
                streaming=True,
                httpx_client=httpx_client,
            )

            factory = ClientFactory(config=config)
            client = factory.create(final_agent_card_to_use)
            logger.info("A2AClient initialized")

            message = Message(
                message_id=str(uuid4()),
                role=Role.user,
                parts=[Part(root=TextPart(text=user_message))],
            )

            try:
                stream = client.send_message(message)
            except Exception as e:
                error_message = f"Error sending message: {str(e)}"
                logger.error(error_message)
                return {"success": False, "error": error_message}

            async for event in stream:
                if hasattr(event, "parts") and event.parts:  # type: ignore
                    if hasattr(event.parts[0], "root"):  # type: ignore
                        if hasattr(event.parts[0].root, "text"):  # type: ignore
                            response_text.append(event.parts[0].root.text)  # type: ignore

        return {
            "success": True,
            "response": (
                "".join(response_text) if response_text else "No response received"
            ),
        }

    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {"success": False, "error": error_message}


@app.route("/")
def index():
    """Render the main UI page."""
    return render_template("index.html")


@app.route("/callback")
def oauth_callback():
    """Handle OAuth2 callback and exchange code for token."""
    try:
        # Get authorization code and state from callback
        code = request.args.get("code")
        state = request.args.get("state")
        
        if not code:
            error = request.args.get("error", "Unknown error")
            error_description = request.args.get("error_description", "")
            logger.error(f"OAuth error: {error} - {error_description}")
            return jsonify({"error": f"OAuth error: {error} - {error_description}"}), 400
        
        # Verify state to prevent CSRF
        if state != session.get("oauth_state"):
            logger.error("State mismatch - possible CSRF attack")
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Retrieve config from session
        client_id = session.get("client_id")
        client_secret = session.get("client_secret")
        token_endpoint = session.get("token_endpoint")
        redirect_uri = session.get("redirect_uri")
        
        if not all([client_id, client_secret, token_endpoint, redirect_uri]):
            return jsonify({"error": "Missing OAuth configuration in session"}), 400
        
        # Exchange code for token
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            access_token = loop.run_until_complete(
                exchange_code_for_token(
                    str(client_id),
                    str(client_secret),
                    str(token_endpoint),
                    code,
                    str(redirect_uri)
                )
            )
            
            # Store access token in session
            session["access_token"] = access_token
            logger.info("Successfully obtained access token")
            
            # Clean up OAuth state
            session.pop("oauth_state", None)
            session.pop("client_id", None)
            session.pop("client_secret", None)
            session.pop("token_endpoint", None)
            session.pop("redirect_uri", None)
            
            return """
            <html>
                <body>
                    <h1>Authentication Successful!</h1>
                    <p>You can now close this window and return to the application.</p>
                    <script>
                        window.close();
                    </script>
                </body>
            </html>
            """
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Error in OAuth callback: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/send-message", methods=["POST", "GET"])
def send_message():
    """API endpoint to send a message to the agent."""
    if request.method == "GET":
        user_message = request.args.get("message", "Give me a hello world")
        oidc_scopes = request.args.get("oidc_scopes", "")
    else:
        data = request.get_json()
        user_message = data.get("message", "Give me a hello world")
        oidc_scopes = data.get("oidc_scopes", "")
    
    # Ensure "openid" scope is always included
    scopes = oidc_scopes.split() if oidc_scopes else []
    if "openid" not in scopes:
        scopes.append("openid")
    normalized_scopes = " ".join(scopes)
    
    # Get access token from session
    access_token = session.get("access_token")
    stored_scopes = session.get("oidc_scopes", "")
    
    # If OAuth is configured and no access token, or scopes have changed, return auth URL
    if OPENID_CONNECT_PROVIDER_NAME and OPENID_CONNECT_CLIENT_NAME:
        if not access_token or (normalized_scopes and normalized_scopes != stored_scopes):
            # Store the requested scopes for this flow
            session["requested_oidc_scopes"] = normalized_scopes
            auth_url, error = get_oauth_auth_url(normalized_scopes)
            if error:
                return jsonify({"success": False, "error": error}), 500
            return jsonify({"success": False, "requires_auth": True, "auth_url": auth_url})

    # Run the async function in a new event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(
            send_agent_request(user_message, access_token)
        )
        return jsonify(result)
    finally:
        loop.close()

@app.route("/api/logout", methods=["POST"])
def logout():
    """Clear the OAuth session."""
    session.pop("access_token", None)
    session.pop("oidc_scopes", None)
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)

# Made with Bob
