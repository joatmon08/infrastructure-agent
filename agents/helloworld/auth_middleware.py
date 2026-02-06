import httpx
import hvac
import jwt
import logging

from a2a.types import AgentCard, HTTPAuthSecurityScheme, OpenIdConnectSecurityScheme

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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

class JWTAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Starlette,
        agent_card: AgentCard,
        public_paths: list[str],
        vault_client: hvac.Client,
    ):
        super().__init__(app)
        self.agent_card = agent_card
        self.public_paths = set(public_paths or [])
        self.vault_client = vault_client

        self.a2a_auth = {}        

        for sec_req in agent_card.security or []:

            if not sec_req:
                break

            for name, scopes in sec_req.items():
                sec_scheme = self.agent_card.security_schemes.get(name).root

                if not isinstance(sec_scheme, HTTPAuthSecurityScheme):
                    raise NotImplementedError('Only HTTPAuthSecurityScheme is supported.')

                self.a2a_auth = { 'required_scopes': scopes }


    ## Use Vault's API to introspect token - ensures that it is active
    async def verify_token(self, jwt_token) -> bool:
        try:
            response = self.vault_client.secrets.identity.introspect_signed_id_token(jwt_token)
            return response['active']
        except Exception as e:
            logger.error(f"Failed to decode token: {str(e)}")
            return False
        

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
            if self.a2a_auth:
                valid_token = await self.verify_token(access_token)

                if not valid_token:
                    logger.error(f"Invalid or expired access token")
                    return self._unauthorized(f'Authentication failed: invalid or expired access token', request)

                payload = None

                try:
                    payload = jwt.decode(access_token, options={'verify_signature': False})
                except Exception as e:
                    logger.error(f"Failed to decode token: {str(e)}")
                    return self._unauthorized(f'Authentication failed: failed to decode token', request)

                scopes = payload.get('scope', '').split()

                missing_scopes = [
                    s
                    for s in self.a2a_auth['required_scopes']
                    if s not in scopes
                ]

                if missing_scopes:
                    return self._forbidden(
                        f'Missing required scopes: {missing_scopes}', request
                    )
        except Exception as e:
            return self._forbidden(f'Authentication failed: {e}', request)

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

class OIDCAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Starlette,
        agent_card: AgentCard,
        public_paths: list[str],
        userinfo_endpoint: str,
    ):
        super().__init__(app)
        self.agent_card = agent_card
        self.public_paths = set(public_paths or [])
        self.userinfo_endpoint = userinfo_endpoint

        scopes = get_scopes_from_agent_card(self.agent_card)
        self.a2a_auth = {"required_scopes": scopes}

    async def get_userinfo(self, access_token):
        try:
            userinfo = httpx.get(
                f"{self.userinfo_endpoint}",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            return userinfo.json()
        except Exception as e:
            logger.error(f"Failed to get userinfo with token: {str(e)}")
            return None

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public paths and anonymous access
        if path in self.public_paths or not self.a2a_auth:
            return await call_next(request)

        # Authenticate the request
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return self._unauthorized(
                "Missing or malformed Authorization header.", request
            )

        access_token = auth_header.split("Bearer ")[1]

        try:
            if self.a2a_auth:
                userinfo = await self.get_userinfo(access_token)

                if not userinfo:
                    logger.error(f"Invalid or expired access token")
                    return self._unauthorized(
                        f"Authentication failed: invalid or expired access token",
                        request,
                    )

                missing_scopes = []

                if self.a2a_auth["required_scopes"]:
                    for scope in self.a2a_auth["required_scopes"]:
                        scope_key, scope_value = scope.split(":")
                        if (
                            scope_key not in userinfo.keys()
                            or scope_value != userinfo.get(scope_key)
                        ):
                            missing_scopes.append(scope)

                    if missing_scopes:
                        logger.error(f"Missing required scopes: {missing_scopes}")
                        return self._forbidden(
                            f"Missing required scopes: {missing_scopes}", request
                        )

        except Exception as e:
            return self._forbidden(f"Authentication failed: {e}", request)

        return await call_next(request)

    def _forbidden(self, reason: str, request: Request):
        accept_header = request.headers.get("accept", "")
        if "text/event-stream" in accept_header:
            return PlainTextResponse(
                f"error forbidden: {reason}",
                status_code=403,
                media_type="text/event-stream",
            )
        return JSONResponse({"error": "forbidden", "reason": reason}, status_code=403)

    def _unauthorized(self, reason: str, request: Request):
        accept_header = request.headers.get("accept", "")
        if "text/event-stream" in accept_header:
            return PlainTextResponse(
                f"error unauthorized: {reason}",
                status_code=401,
                media_type="text/event-stream",
            )
        return JSONResponse(
            {"error": "unauthorized", "reason": reason}, status_code=401
        )
