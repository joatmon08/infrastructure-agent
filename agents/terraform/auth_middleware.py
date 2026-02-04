import jwt
import logging
import hvac
import os

from a2a.types import AgentCard, HTTPAuthSecurityScheme
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

PUBLIC_KEY_ENDPOINT = os.getenv("PUBLIC_KEY_ENDPOINT")
ISSUER = os.getenv("VAULT_ADDR")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def verify_token(jwt_token) -> bool:
    vault_client = hvac.Client(
            url = os.environ['VAULT_ADDR'],
            token = os.environ['VAULT_TOKEN'],
            namespace = os.environ['VAULT_NAMESPACE'],
    )
    response = vault_client.secrets.identity.introspect_signed_id_token(jwt_token)
    return response['active'] == True

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Starlette,
        agent_card: AgentCard,
        public_paths: list[str],
    ):
        super().__init__(app)
        self.agent_card = agent_card
        self.public_paths = set(public_paths or [])

        # Process the AgentCard to identify what (if any) Security Requirements are defined at the root of the
        # AgentCard, indicating agent-level authentication/authorization.

        # Use app state for this demonstration (simplicity)
        self.a2a_auth = {}

        for sec_req in agent_card.security or []:

            if not sec_req:
                break

            for name, scopes in sec_req.items():
                sec_scheme = self.agent_card.security_schemes.get(name).root

                if not isinstance(sec_scheme, HTTPAuthSecurityScheme):
                    raise NotImplementedError('Only HTTPAuthSecurityScheme is supported.')

                self.a2a_auth = { 'required_scopes': scopes }
        

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
                valid_token = await verify_token(access_token)

                if not valid_token:
                    logger.error(f"Invalid or expired access token")
                    return self._unauthorized(f'Authentication failed: invalid or expired access token', request)

                payload = None

                try:
                    payload = jwt.decode(access_token, options={'verify_signature': False})
                except Exception as e:
                    logger.error(f"Failed to decode token: {str(e)}")

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