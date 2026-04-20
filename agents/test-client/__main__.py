import asyncio
import json
import logging
import os
import secrets
from typing import Optional
from urllib.parse import urlencode
from uuid import uuid4

from flask import Flask, render_template, jsonify, request, redirect, session, url_for
from flask_cors import CORS

import httpx

from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import AgentCard, Message, Role, Part, TextPart

from a2a.utils.constants import (
    AGENT_CARD_WELL_KNOWN_PATH,
    EXTENDED_AGENT_CARD_PATH,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment variables
AGENT_SERVER_URL = os.getenv("AGENT_URL", "http://localhost:9999")
APP_PORT = int(os.getenv("APP_PORT", 9000))

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", None)
VAULT_TOKEN_PATH = os.getenv("VAULT_TOKEN_PATH", "./token")
VAULT_OAUTH_DELEGATION_ROLE = os.getenv("VAULT_OAUTH_DELEGATION_ROLE", "test-client")

OIDC_PROVIDER_CONFIG_PATH = os.getenv("OIDC_PROVIDER_CONFIG_PATH", "./oidc_provider.json")
CLIENT_SECRETS_PATH = os.getenv("CLIENT_SECRETS_PATH", "./client_secrets.json")
ACTOR_TOKEN_PATH = os.getenv("ACTOR_TOKEN_PATH", "./actor_token")

# TLS verification
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() == "true"

## Base URL for the application (used for OAuth redirect URIs)
## This prevents Host header injection attacks
BASE_URL = os.getenv("BASE_URL", f"http://localhost:{APP_PORT}")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
CORS(app, origins=["*"])


class OAuth2Delegation():
    def __init__(self, subject_token, actor_token, audience, scope):
        self.subject_token = subject_token
        self.actor_token = actor_token
        self.audience = audience
        self.scope = scope

    def getExchangeToken(self):
        try:
            with open(VAULT_TOKEN_PATH, "r") as f:
                vault_token = f.read().strip()
        except Exception as e:
            raise ValueError(f"Cannot load Vault token from {VAULT_TOKEN_PATH}: {str(e)}")

        if not vault_token:
            raise ValueError(f"Vault token file {VAULT_TOKEN_PATH} is empty")

        request_params = {
            "subject_token": self.subject_token,
            "actor_token": self.actor_token,
            "audience": self.audience,
            "scope": self.scope,
        }

        logger.info(vault_token)

        headers = {
            "X-Vault-Token": vault_token,
        }

        if VAULT_NAMESPACE:
            headers["X-Vault-Namespace"] = VAULT_NAMESPACE

        endpoint = f"{VAULT_ADDR.rstrip('/')}/v1/sts/token/{VAULT_OAUTH_DELEGATION_ROLE}"

        logger.info(f"Calling Vault STS token exchange endpoint for delegation: {endpoint}")

        try:
            response = httpx.get(
                endpoint,
                params=request_params,
                headers=headers,
                verify=VERIFY_TLS,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ValueError(
                f"Vault STS token exchange failed with status {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise ValueError(f"Vault STS token exchange failed: {str(e)}") from e

        token_response = response.json()
        if token_response.get("data") is None:
            raise ValueError("Vault STS token exchange response did not include data")
        
        access_token = token_response.get("data").get("access_token")

        if not access_token:
            raise ValueError("Vault STS token exchange response did not include access_token")

        return access_token

class OIDCAuthenticationConfig:
    def __init__(self, client_secrets_path, oidc_provider_config_path, oidc_scopes=""):
        # Ensure "openid" scope is always included
        scopes = oidc_scopes.split() if oidc_scopes else []
        if "openid" not in scopes:
            scopes.append("openid")
        self.scope = " ".join(scopes)

        try:
            with open(client_secrets_path, 'r') as f:
                client_secrets = json.load(f)
            
            self.client_id = client_secrets["client_id"]
            self.client_secret = client_secrets["client_secret"]
            self.redirect_uris = client_secrets["redirect_uris"]

        except Exception as e:
            raise ValueError(f"Cannot load client secrets from {client_secrets_path}: {str(e)}")

        try:
            with open(oidc_provider_config_path, 'r') as f:
                oidc_provider = json.load(f)

            self.authorization_endpoint = oidc_provider["authorization_endpoint"]
            self.issuer = oidc_provider["issuer"]
            self.token_endpoint = oidc_provider["token_endpoint"]
            self.userinfo_endpoint = oidc_provider["userinfo_endpoint"]
        
        except Exception as e:
            raise ValueError(f"Cannot load OIDC provider configuration from {oidc_provider_config_path}: {str(e)}")

    def validate_redirect_uri(self, redirect_uri):
        if redirect_uri not in self.redirect_uris:
            raise ValueError(f"Redirect URI {redirect_uri} not in allowed list")


def get_actor_token(actor_token_path):
    try:
        with open(actor_token_path, 'r') as f:
            actor_token = f.read().strip()
        
    except Exception as e:
        raise ValueError(f"Cannot load actor token from {actor_token_path}: {str(e)}")

    if not actor_token:
        raise ValueError(f"Actor token file {ACTOR_TOKEN_PATH} is empty")

    return actor_token


def get_oauth_auth_url(client_secrets_path, oidc_provider_config_path, oidc_scopes: str = ""):
    """Generate OAuth2 authorization URL and return it."""
    try:
        # Build redirect URI from current request
        redirect_uri = f"{BASE_URL}{url_for('oauth_callback')}"
        
        # Get OIDC configuration
        config = OIDCAuthenticationConfig(client_secrets_path, oidc_provider_config_path, oidc_scopes)
        
        if not config.authorization_endpoint or not config.client_id:
            logger.error("OIDC configuration missing required values")
            raise ValueError(f"OIDC configuration missing required values")
        
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
        logger.info("Generated authorization URL")
        
        return auth_url, None
    except ValueError as e:
        logger.error(f"Error generating OAuth authorization URL: {str(e)}")
        return None, str(e)
    except Exception as e:
        logger.error(f"Error generating OAuth authorization URL: {str(e)}")
        return None, str(e)


async def exchange_code_for_token(client_id: str, client_secret: str, token_endpoint: str, code: str, redirect_uri: str) -> dict:
    """Exchange authorization code for access token."""
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    
    async with httpx.AsyncClient(verify=VERIFY_TLS) as client:
        response = await client.post(
            token_endpoint,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        response.raise_for_status()
        token_response = response.json()
        return token_response

async def get_delegation_access_token(subject_token, audience, scope):
    """Get delegation access token for agent."""
    actor_token = get_actor_token(ACTOR_TOKEN_PATH)
    delegation = OAuth2Delegation(subject_token, actor_token, audience, scope)
    return delegation.getExchangeToken()

async def send_agent_request(user_message: str, access_token: Optional[str] = None) -> dict:
    """Send a request to the agent and return the response."""
    base_url = AGENT_SERVER_URL
    response_text = []
    error_message = None

    try:
        async with httpx.AsyncClient(http2=True, timeout=60, verify=VERIFY_TLS) as httpx_client:
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
                    if access_token:
                        httpx_client.headers["Authorization"] = f"Bearer {access_token}"
                    else:
                        error_message = "OAuth authentication required but no access token provided"
                        logger.error(error_message)
                        return {"success": False, "error": error_message, "requires_auth": True}

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
                logger.info("Sending message")
                response = ""
                async for event in client.send_message(message):
                    if event.kind == "message":
                        parts = event.parts
                        for part in parts:
                            response += part.root.text
                return {"success": True, "response": response}
            except Exception as e:
                error_message = f"Error sending message: {str(e)}"
                logger.error(error_message)
                return {"success": False, "error": error_message}

    except httpx.HTTPStatusError as e:
        error_message = f"HTTP Status Error: {str(e)}"
        logger.error(error_message)
        return {"success": False, "error": error_message}
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logger.error(error_message, exc_info=True)
        return {"success": False, "error": error_message}


@app.route("/")
def index():
    """Render the main UI page."""
    return render_template("index.html")


@app.route("/login")
def login():
    scopes = request.args.get("scopes", "")
    scope_list = scopes.split() if scopes else []
    if "openid" not in scope_list:
        scope_list.append("openid")
    normalized_scopes = " ".join(scope_list)
    auth_url, error = get_oauth_auth_url(CLIENT_SECRETS_PATH, OIDC_PROVIDER_CONFIG_PATH, oidc_scopes=normalized_scopes)
    if error:
        return jsonify({"error": error}), 500
    return redirect(auth_url, code=307)


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
        
        # Retrieve and validate OAuth config from session
        oauth_keys = ["client_id", "client_secret", "token_endpoint", "redirect_uri"]
        oauth_config = {key: session.get(key) for key in oauth_keys}
        
        if not all(oauth_config.values()):
            return jsonify({"error": "Missing OAuth configuration in session"}), 400
        
        client_id, client_secret, token_endpoint, redirect_uri = oauth_config.values()
        
        # Exchange code for token
        response = asyncio.run(
            exchange_code_for_token(
                client_id, client_secret, token_endpoint, code, redirect_uri
            )
        )

        # Store id token in session
        session['id_token'] = response['id_token']
        session['access_token'] = response['access_token']
        
        # Clean up OAuth state
        cleanup_keys = ["oauth_state", "client_id", "client_secret", "token_endpoint", "redirect_uri"]
        for key in cleanup_keys:
            session.pop(key, None)
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {str(e)}", exc_info=True)
        return jsonify({"error": f"OAuth callback failed. {str(e)}"}), 500


@app.route("/api/delegate-access", methods=["POST"])
async def delegate_access():
    """Exchange the current subject token for a delegation access token."""
    data = request.get_json() or {}
    audience = (data.get("audience") or "").strip()
    scope = (data.get("scope") or "").strip()
    subject_token = session.get("id_token")

    if not subject_token:
        return jsonify({"success": False, "error": "No subject token found in session. Please log in first."}), 401

    if not audience:
        return jsonify({"success": False, "error": "A2A agent server is required."}), 400

    if not scope:
        return jsonify({"success": False, "error": "Scope is required."}), 400

    try:
        access_token = await get_delegation_access_token(subject_token, audience, scope)
    except Exception as e:
        logger.error(f"Delegation token exchange failed: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Delegation token exchange failed: {str(e)}"}), 500

    if not access_token:
        return jsonify({"success": False, "error": "Token exchange for delegation failed, no exchange token"}), 401

    session["access_token"] = access_token

    return jsonify({"success": True, "access_token": access_token})


@app.route("/api/send-message", methods=["POST", "GET"])
async def send_message():
    """API endpoint to send a message to the agent."""
    if request.method == "GET":
        user_message = request.args.get("message", "Give me a hello world")
        audience = (request.args.get("audience") or AGENT_SERVER_URL).strip()
        scope = (request.args.get("scope") or "").strip()
    else:
        data = request.get_json() or {}
        user_message = data.get("message", "Give me a hello world")
    
    # Get access token from session
    access_token = session.get("access_token")
    
    if not access_token:
        return jsonify({"success": False, "error": "Token exchange for delegation failed, no access token"}), 401

    return await send_agent_request(user_message, access_token)


@app.route("/api/auth-status", methods=["GET"])
def auth_status():
    """Return whether the session has a valid access token and the scopes."""
    has_token = bool(session.get("access_token"))
    scopes = session.get("oidc_scopes", "")
    return jsonify({
        "authenticated": has_token,
        "scopes": scopes
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    """Clear the OAuth session."""
    session.pop("access_token", None)
    session.pop("oidc_scopes", None)
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)

# Made with Bob
