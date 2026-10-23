"""Gemeinsame Fixtures. Alle HTTP-Requests laufen gegen respx-Mocks, nie gegen echte APIs."""

import os
import sys

import pytest
import respx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TRMM_URL = "https://api.rmm.example.com"
TRMM_KEY = "trmm-test-api-key-value"
MCP_KEY = "test-mcp-api-key-0123456789abcdef0123456789abcdef"
WIN_ID = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"
LIN_ID = "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zyxw"
OFF_ID = "OfflineAgentIdentifier000000000000000000"
DC_ID = "DomainControllerIdentifier00000000000000"

AGENTS = [
    {"id": 1, "hostname": "PC-OFFICE01", "agent_id": WIN_ID, "client_name": "Example AG", "site_name": "Hauptsitz",
     "status": "online", "plat": "windows", "monitoring_type": "workstation", "logged_username": "anna"},
    {"id": 2, "hostname": "nas-backup", "agent_id": LIN_ID, "client_name": "Example AG", "site_name": "Hauptsitz",
     "status": "online", "plat": "linux", "monitoring_type": "server"},
    {"id": 3, "hostname": "PC-LAGER", "agent_id": OFF_ID, "client_name": "Muster GmbH", "site_name": "Lager",
     "status": "offline", "plat": "windows", "monitoring_type": "workstation"},
    {"id": 4, "hostname": "SRV-DC01", "agent_id": DC_ID, "client_name": "Muster GmbH", "site_name": "Lager",
     "status": "online", "plat": "windows", "monitoring_type": "server"},
]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    values = {
        "TRMM_URL": TRMM_URL,
        "TRMM_API_KEY": TRMM_KEY,
        "TRMM_TLS_VERIFY": "1",
        "TRMM_READ_ONLY": "0",
        "MCP_ALLOW_EXEC": "1",
        "PROTECTED_AGENTS": "srv-dc*",
        "MCP_API_KEY": MCP_KEY,
    }
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    for k in ("APP_VERSION", "GIT_SHA", "BUILD_TIME", "BLOCKED_COMMAND_PATTERNS"):
        monkeypatch.delenv(k, raising=False)
    from tactical_mcp import app, config

    config.reset()
    app.set_client(None)
    yield values
    config.reset()
    app.set_client(None)


@pytest.fixture
def mock():
    with respx.mock(base_url=TRMM_URL, assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.fixture
def agents(mock):
    mock.get("/agents/").respond(200, json=AGENTS)
    return mock


def written(router):
    return [c.request for c in router.calls if c.request.method in ("POST", "PUT", "DELETE", "PATCH")]
