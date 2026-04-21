import logging
from typing import Optional

import httpx
import jwt
from jwt import PyJWKClient

from a2a.types import AgentCard, HTTPAuthSecurityScheme, OpenIdConnectSecurityScheme

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OpenIDConfig:
    """
    Encapsulates OpenID Connect configuration fetched from the discovery endpoint.
    """
    
    def __init__(self, openid_connect_url: str, verify_tls: bool = True):
        """
        Initialize by fetching the OIDC configuration from the discovery URL.
        
        Args:
            openid_connect_url: The OpenID Connect discovery URL (/.well-known/openid-configuration)
            verify_tls: Whether to verify TLS certificates (default: True)
            
        Raises:
            ValueError: If the configuration cannot be fetched or parsed
        """
        self.openid_connect_url = openid_connect_url
        self.verify_tls = verify_tls
        self._config = self._fetch_configuration()
    
    def _fetch_configuration(self) -> dict:
        """
        Fetch the OpenID Connect configuration from the .well-known endpoint.
        
        Returns:
            dict: The OIDC configuration
            
        Raises:
            ValueError: If the configuration cannot be fetched or parsed
        """
        try:
            if not self.verify_tls:
                logger.warning("TLS verification is disabled for OIDC configuration fetch")
            
            response = httpx.get(self.openid_connect_url, verify=self.verify_tls)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Failed to fetch OIDC configuration: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise ValueError(f"Failed to fetch OIDC configuration from {self.openid_connect_url}: {e}")
        except Exception as e:
            raise ValueError(f"Failed to parse OIDC configuration: {e}")
    
    @property
    def jwks_uri(self) -> str:
        """
        Get the JWKS URI from the OIDC configuration.
        
        Returns:
            str: The JWKS URI
            
        Raises:
            ValueError: If jwks_uri is not found in the configuration
        """
        jwks_uri = self._config.get('jwks_uri')
        if not jwks_uri:
            raise ValueError("jwks_uri not found in OIDC configuration")
        return jwks_uri
    
    @property
    def issuer(self) -> str:
        """
        Get the issuer from the OIDC configuration.
        
        Returns:
            str: The issuer URL
            
        Raises:
            ValueError: If issuer is not found in the configuration
        """
        issuer = self._config.get('issuer')
        if not issuer:
            raise ValueError("issuer not found in OIDC configuration")
        return issuer
    
    @property
    def token_endpoint(self) -> Optional[str]:
        """Get the token endpoint if available."""
        return self._config.get('token_endpoint')

    
    def get(self, key: str, default=None):
        """
        Get any attribute from the OIDC configuration.
        
        Args:
            key: The configuration key to retrieve
            default: Default value if key is not found
            
        Returns:
            The value associated with the key, or default if not found
        """
        return self._config.get(key, default)


def get_scopes_from_agent_card(agent_card):
    for sec_req in agent_card.security or []:
        if not sec_req:
            break

        for name, scopes in sec_req.items():
            if agent_card.security_schemes == None:
                raise NotImplementedError(f"No security scheme defined")

            if agent_card.security_schemes.get(name) == None:
                raise NotImplementedError(f"No security scheme defined for {name}")

            if agent_card.security_schemes.get(name).root == None:
                raise NotImplementedError(f"No security scheme defined for {name}")

            sec_scheme = agent_card.security_schemes.get(name).root

            if not isinstance(sec_scheme, HTTPAuthSecurityScheme) and not isinstance(
                sec_scheme, OpenIdConnectSecurityScheme
            ):
                raise NotImplementedError(
                    "Only HTTPAuthSecurityScheme, OpenIdConnectSecurityScheme are supported."
                )

            return scopes

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        agent_card: AgentCard,
        public_paths: list[str],
        openid_connect_url: str,
        verify_tls: bool = True,
    ):
        super().__init__(app)
        self.agent_card = agent_card
        self.public_paths = set(public_paths or [])
        
        # Fetch OIDC configuration dynamically
        self.oidc_config = OpenIDConfig(openid_connect_url, verify_tls=verify_tls)
        self.jwks_uri = self.oidc_config.jwks_uri
        self.issuer = self.oidc_config.issuer
        self.jwks_client = PyJWKClient(self.jwks_uri)
        
        # The audience should match the agent name
        self.audience = agent_card.name

        scopes = get_scopes_from_agent_card(self.agent_card)
        self.a2a_auth = {"required_scopes": scopes}

    def _validate_and_decode_token(self, access_token: str) -> dict:
        """
        Validate and decode the access token with comprehensive checks.
        
        This method performs:
        - Signature verification against JWKS endpoint
        - Expiration time validation
        - Issuer validation
        - Audience validation
        
        Args:
            access_token: The JWT access token to validate
            
        Returns:
            dict: The decoded token payload
            
        Raises:
            jwt.InvalidTokenError: If token validation fails
        """
        signing_key = self.jwks_client.get_signing_key_from_jwt(access_token)
        
        # Decode and validate the token with all checks enabled
        # By providing issuer and audience parameters, PyJWT automatically validates them
        # The options dict controls which claims are required and verified
        return jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"],
            issuer=self.issuer,
            audience=self.audience,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
                "require": ["exp", "iss", "aud"],
            },
        )

    def _get_token_scopes(self, payload: dict) -> list[str]:
        scope_claim = payload.get("scope", "")
        if isinstance(scope_claim, str):
            return scope_claim.split()
        if isinstance(scope_claim, list):
            return [str(scope) for scope in scope_claim]
        return []

    def _get_missing_scopes(self, access_token_scopes: list[str]) -> list[str]:
        if not self.a2a_auth["required_scopes"]:
            return []

        return [
            scope
            for scope in self.a2a_auth["required_scopes"]
            if scope not in access_token_scopes
        ]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public paths and anonymous access
        if path in self.public_paths or not self.a2a_auth:
            return await call_next(request)

        # Authenticate the request
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return self._unauthorized(
                'Missing or malformed Authorization header.', request
            )

        access_token = auth_header.split('Bearer ')[1]

        try:
            payload = self._validate_and_decode_token(access_token)
            missing_scopes = self._get_missing_scopes(self._get_token_scopes(payload))

            if missing_scopes:
                logger.error(f"Missing required scopes: {missing_scopes}")
                return self._forbidden(
                    f'Missing required scopes: {missing_scopes}', request
                )

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return self._unauthorized(f'Authentication failed: {e}', request)

        return await call_next(request)

    def _forbidden(self, reason: str, request: Request):
        accept_header = request.headers.get('accept', '')
        if 'text/event-stream' in accept_header:
            return PlainTextResponse(
                f'error forbidden: {reason}',
                status_code=403,
                media_type='text/event-stream',
            )
        return JSONResponse(
            {'error': 'forbidden', 'reason': reason}, status_code=403
        )

    def _unauthorized(self, reason: str, request: Request):
        accept_header = request.headers.get('accept', '')
        if 'text/event-stream' in accept_header:
            return PlainTextResponse(
                f'error unauthorized: {reason}',
                status_code=401,
                media_type='text/event-stream',
            )
        return JSONResponse(
            {'error': 'unauthorized', 'reason': reason}, status_code=401
        )