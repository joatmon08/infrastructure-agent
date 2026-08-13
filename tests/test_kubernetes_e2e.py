import os

import hvac
import httpx
import pytest
from kubernetes import client, config

REQUIRED_ENV_VARS = ["KUBERNETES_CONTEXT", "VAULT_ADDR", "VAULT_TOKEN"]
REQUIRED_SUMMARIZER_ENV_VARS = ["SUMMARIZER_URL"]


@pytest.fixture(scope="session", autouse=True)
def check_environment_variables():
    """
    Runs automatically once before the first test.
    Aborts the entire test run if required environment variables are missing.
    """
    missing_vars = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]

    if missing_vars:
        pytest.exit(
            f"CRITICAL ERROR: Missing required environment variables: {', '.join(missing_vars)}",
            returncode=1,
        )


@pytest.fixture
def v1():
    k8s_context = os.environ["KUBERNETES_CONTEXT"]
    config.load_kube_config(context=k8s_context)
    return client.CoreV1Api()


@pytest.fixture
def nodes(v1):
    response = v1.list_node()
    return response.items


@pytest.fixture
def vault_pods(v1):
    response = v1.list_namespaced_pod(namespace="vault")
    return [(item.metadata.labels, item.status.phase) for item in response.items]


@pytest.fixture
def vault():
    vault_addr = os.environ["VAULT_ADDR"]
    vault_token = os.environ["VAULT_TOKEN"]
    vault_tls_verify = False if os.environ.get("VAULT_SKIP_VERIFY") else True
    return hvac.Client(url=vault_addr, token=vault_token, verify=vault_tls_verify)


@pytest.fixture
def summarizer_url():
    value = os.environ.get("SUMMARIZER_URL")
    if not value:
        pytest.skip("SUMMARIZER_URL is required for summarizer end-to-end tests")
    return value.rstrip("/")


@pytest.fixture
def summarizer_client():
    with httpx.Client(timeout=120.0, follow_redirects=True) as client_instance:
        yield client_instance


@pytest.mark.kubernetes
def test_k8s_has_1_gpu_node(nodes):
    assert len([node for node in nodes if "node.kubernetes.io/gpu" in node.metadata.labels]) == 1, "At least 1 Kubernetes node must have GPU"


@pytest.mark.kubernetes
def test_k8s_vault_is_running(vault_pods):
    vault_statefulset_pods = [pod for pod in vault_pods if "statefulset.kubernetes.io/pod-name" in pod[0] and pod[0]["app.kubernetes.io/name"] == "vault" and pod[1] == "Running"]
    assert len(vault_statefulset_pods) == 3, "3 Vault server pods must be Running"


@pytest.mark.kubernetes
def test_k8s_vault_agent_injector_is_running(vault_pods):
    vault_agent = [pod for pod in vault_pods if pod[0]["app.kubernetes.io/name"] == "vault-agent-injector" and pod[1] == "Running"]
    assert len(vault_agent) == 1, "Vault agent injector pod must be Running"


@pytest.mark.kubernetes
def test_k8s_vault_agent_secrets_operator_is_running(vault_pods):
    vault_operator = [pod for pod in vault_pods if pod[0]["app.kubernetes.io/name"] == "vault-secrets-operator" and pod[1] == "Running"]
    assert len(vault_operator) == 1, "Vault Secrets Operator pod must be Running"


@pytest.mark.vault
def test_vault_is_initialized(vault):
    assert vault.sys.is_initialized()


@pytest.mark.vault
def test_vault_is_unsealed(vault):
    assert not vault.sys.is_sealed()


@pytest.mark.vault
def test_vault_sts_plugin_is_registered(vault):
    plugins = vault.read("/sys/plugins/catalog")
    assert len([plugin for plugin in plugins["data"]["detailed"] if plugin["name"] == "vault-plugin-secrets-oauth-token-exchange"]) == 1


@pytest.mark.summarizer
def test_summarizer_agent_card_is_served(summarizer_client, summarizer_url):
    response = summarizer_client.get(f"{summarizer_url}/.well-known/agent-card.json")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "summarizer-agent"
    assert payload["defaultInputModes"] == ["text"]
    assert payload["defaultOutputModes"] == ["text"]


@pytest.mark.summarizer
def test_summarizer_jsonrpc_returns_summary(summarizer_client, summarizer_url):
    response = summarizer_client.post(
        summarizer_url,
        headers={"A2A-Version": "1.0"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "messageId": "summarizer-e2e-message",
                    "role": "ROLE_USER",
                    "parts": [{"text": "HashiCorp Vault secures secrets for applications."}],
                }
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert "error" not in payload, payload

    result = payload.get("result", {})
    task = result.get("task") or result
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    summary = task["status"]["message"]["parts"][0]["text"]
    assert isinstance(summary, str)
    assert summary.strip() != ""
