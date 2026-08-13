import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

from google.protobuf.json_format import MessageToDict

from starlette.testclient import TestClient

from a2a.server.request_handlers.response_helpers import agent_card_to_dict
from a2a.types import Message, Part, Role, SendMessageRequest

MODULE_PATH = Path(__file__).resolve().parents[1] / "__main__.py"


def load_main_module():
    spec = importlib.util.spec_from_file_location("summarizer_main", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(MODULE_PATH.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def load_summarizer_module(auth_enabled: bool = True):
    os.environ["AUTH_ENABLED"] = "true" if auth_enabled else "false"
    if auth_enabled:
        os.environ["OPENID_CONNECT_URL"] = (
            "https://vault.example.com/v1/sts/.well-known/openid-configuration"
        )
    else:
        os.environ.pop("OPENID_CONNECT_URL", None)
    os.environ["VERIFY_TLS"] = "true"
    return load_main_module()


def test_agent_card_is_served_on_well_known_path():
    summarizer_module = load_summarizer_module()
    with patch.object(
        summarizer_module.OpenIDConfig,
        "_fetch_configuration",
        return_value={
            "issuer": "https://vault.example.com",
            "jwks_uri": "https://vault.example.com/jwks.json",
        },
    ):
        app = summarizer_module.build_app()
        with TestClient(app) as client:
            response = client.get("/.well-known/agent-card.json")

    assert response.status_code == 200
    assert response.json() == agent_card_to_dict(summarizer_module.build_agent_card())


def test_send_message_uses_expected_prompt_and_returns_summary():
    summarizer_module = load_summarizer_module()
    request = SendMessageRequest(
        message=Message(
            role=Role.ROLE_USER,
            message_id="test-message-id",
            parts=[Part(text="This is a long article.")],
        )
    )

    with patch.object(
        summarizer_module.OpenIDConfig,
        "_fetch_configuration",
        return_value={
            "issuer": "https://vault.example.com",
            "jwks_uri": "https://vault.example.com/jwks.json",
        },
    ):
        with patch.object(
            summarizer_module.auth_middleware,
            "PyJWKClient",
            autospec=True,
        ) as mock_jwk_client:
            mock_jwk_client.return_value.get_signing_key_from_jwt.return_value.key = "key"
            with patch.object(
                summarizer_module.auth_middleware.jwt,
                "decode",
                return_value={
                    "aud": "summarizer-agent",
                    "iss": "https://vault.example.com",
                    "exp": 9999999999,
                    "scope": "summarizer:summarize",
                },
            ):
                with patch.object(
                    summarizer_module.SummarizerAgent,
                    "invoke",
                    new=AsyncMock(return_value="Short summary."),
                ) as mock_invoke:
                    app = summarizer_module.build_app()
                    with TestClient(app) as client:
                        response = client.post(
                            "/",
                            headers={
                                "Authorization": "Bearer token",
                                "A2A-Version": "1.0",
                            },
                            json={
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "SendMessage",
                                "params": MessageToDict(
                                    request, preserving_proto_field_name=False
                                ),
                            },
                        )

    assert response.status_code == 200
    mock_invoke.assert_awaited_once_with("This is a long article.")
    payload = response.json()
    task = payload["result"]["task"]
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    assert task["status"]["message"]["parts"][0]["text"] == "Short summary."


def test_build_app_succeeds_when_auth_disabled():
    summarizer_module = load_summarizer_module(auth_enabled=False)

    app = summarizer_module.build_app()

    assert app is not None


def test_agent_card_omits_security_when_auth_disabled():
    summarizer_module = load_summarizer_module(auth_enabled=False)

    agent_card = summarizer_module.build_agent_card()

    assert len(agent_card.security_schemes) == 0
    assert len(agent_card.security_requirements) == 0


def test_build_app_requires_openid_connect_url_when_auth_enabled():
    os.environ["AUTH_ENABLED"] = "true"
    os.environ.pop("OPENID_CONNECT_URL", None)
    os.environ["VERIFY_TLS"] = "true"
    summarizer_module = load_main_module()

    try:
        summarizer_module.build_app()
        raise AssertionError("build_app should require OPENID_CONNECT_URL when auth is enabled")
    except ValueError as exc:
        assert str(exc) == "OPENID_CONNECT_URL environment variable must be set when AUTH_ENABLED=true"
