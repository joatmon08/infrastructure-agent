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

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Starlette,
        agent_card: AgentCard,
        public_paths: list[str],
        vault_client: hvac.Client,
        openid_connect_provider_name: str | None,
    ):
        super().__init__(app)
        self.agent_card = agent_card
        self.public_paths = set(public_paths or [])
        self.vault_client = vault_client
        self.openid_connect_provider_name = openid_connect_provider_name

        scopes = get_scopes_from_agent_card(self.agent_card)
        self.a2a_auth = {"required_scopes": scopes}


    async def check_vault_identity_token(self, request: Request, access_token):
        logger.info("Checking Vault identity token")
        valid_token = await self._verify_vault_token(access_token)

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

        missing_scopes = []

        if self.a2a_auth['required_scopes']:
            missing_scopes = [
                s
                for s in self.a2a_auth['required_scopes']
                if s not in scopes
            ]
        
        return missing_scopes

    async def _get_userinfo_endpoint(self, openid_connect_provider_name: str) -> str | None :
        try:
            response = self.vault_client.read(f"/v1/identity/oidc/provider/{openid_connect_provider_name}/.well-known/openid-configuration")
            config = response.json()
            return config['userinfo_endpoint']
        except Exception as e:
            logger.error(f"Failed to get OIDC provider config: {str(e)}")
            return None

    ## Use Vault's API to introspect token - ensures that it is active
    async def _verify_vault_token(self, jwt_token) -> bool:
        try:
            response = self.vault_client.secrets.identity.introspect_signed_id_token(jwt_token)
            return response['active']
        except Exception as e:
            logger.error(f"Failed to decode token: {str(e)}")
            return False

    async def get_userinfo(self, access_token, openid_connect_provider_name):
        try:
            userinfo_endpoint = await self._get_userinfo_endpoint(openid_connect_provider_name)
            userinfo = httpx.get(
                f"{userinfo_endpoint}",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            return userinfo.json()
        except Exception as e:
            logger.error(f"Failed to get userinfo with token: {str(e)}")
            return None

    def check_oidc_scopes(self, userinfo):
        missing_scopes = [ ] 

        if self.a2a_auth["required_scopes"]:
            for scope in self.a2a_auth["required_scopes"]:
                scope_key, scope_value = scope.split(":")
                if (
                    scope_key not in userinfo.keys()
                    or scope_value != userinfo.get(scope_key)
                ):
                    missing_scopes.append(scope)

        return missing_scopes
        

    async def dispatch(self, request: Request, call_next):
        if self.vault_client is None:
            logger.error("No Vault client provided. Cannot connect to identity provider")
            return

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
            missing_scopes = []
    
            if self.a2a_auth:
                if self.openid_connect_provider_name:
                    userinfo = await self.get_userinfo(access_token, self.openid_connect_provider_name)

                    if not userinfo:
                        logger.error(f"Invalid or expired access token")
                        return self._unauthorized(
                            f"Authentication failed: invalid or expired access token",
                            request,
                    )

                    missing_scopes = self.check_oidc_scopes(userinfo)

                else:
                    missing_scopes = await self.check_vault_identity_token(request, access_token)
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