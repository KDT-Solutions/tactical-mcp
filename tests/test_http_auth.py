"""Schutz des MCP-HTTP-Endpunkts (Bearer-Token, fail-safe Start, CORS)."""

import pytest
from starlette.testclient import TestClient

API_KEY = "test-mcp-api-key-0123456789abcdef0123456789abcdef"
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def server():
    from tactical_mcp import server as srv

    return srv


@pytest.fixture
def http_client(server):
    app = server._build_http_app(API_KEY)
    with TestClient(app, base_url="https://tactical-mcp.example.com") as client:
        yield client


def init_request():
    return {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}},
    }


def test_refuses_start_without_api_key(server, monkeypatch):
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server.main()
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server._build_http_app("")
    # Nur Leerzeichen zählt nicht als Token
    with pytest.raises(RuntimeError, match="fehlt"):
        server._build_http_app("   ")


def test_refuses_short_api_key(server, monkeypatch):
    with pytest.raises(RuntimeError, match="zu kurz"):
        server._build_http_app("x" * 31)
    monkeypatch.setenv("MCP_API_KEY", "kurz")
    with pytest.raises(RuntimeError, match="zu kurz"):
        server.main()
    assert server._checked_api_key("  " + "y" * 32 + "\n") == "y" * 32


def test_token_is_trimmed(server):
    app = server._build_http_app(f"  {API_KEY}\n")
    with TestClient(app, base_url="https://tactical-mcp.example.com") as client:
        assert client.get("/healthz", headers={"Authorization": f"Bearer {API_KEY}"}).status_code == 200
        assert client.get("/healthz", headers={"Authorization": f"Bearer {API_KEY}x"}).status_code == 401


def test_rejects_missing_and_wrong_token(http_client):
    assert http_client.post("/mcp", json=init_request(), headers=HEADERS).status_code == 401
    bad = {**HEADERS, "Authorization": "Bearer falsch"}
    assert http_client.post("/mcp", json=init_request(), headers=bad).status_code == 401
    assert http_client.get("/healthz").status_code == 401


def test_accepts_valid_token(http_client):
    ok = {**HEADERS, "Authorization": f"Bearer {API_KEY}"}
    assert http_client.get("/healthz", headers=ok).status_code == 200
    r = http_client.post("/mcp", json=init_request(), headers=ok)
    assert r.status_code == 200
    assert r.json()["result"]["serverInfo"]["name"] == "tactical-mcp"


def test_cors_preflight_without_token(http_client):
    r = http_client.options(
        "/mcp",
        headers={"Origin": "https://claude.ai", "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "authorization,content-type"},
    )
    assert r.status_code == 200


def test_all_tools_registered():
    from tactical_mcp import server  # noqa: F401
    from tactical_mcp.app import mcp

    import asyncio

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    for n in ("trmm_list_agents", "trmm_run_command", "trmm_run_script_code", "trmm_run_script", "trmm_get_event_log"):
        assert n in names
    assert all(n.startswith("trmm_") for n in names)
