"""Script-Ausführung, Agent-Auflösung, Timeouts, Schwärzung."""

import json

import httpx
import pytest

from conftest import TRMM_KEY, WIN_ID, written
from tactical_mcp import app, tools_exec, tools_read
from tactical_mcp.errors import GuardError, UnclearStateError


async def test_run_script_code_payload(agents):
    route = agents.post(f"/scripts/{WIN_ID}/test/").respond(
        200, json={"stdout": "ok", "stderr": "", "retcode": 0, "execution_time": "0.5"}
    )
    code = "$x = Get-Date\nWrite-Output $x"
    r = await tools_exec.trmm_run_script_code(
        "PC-OFFICE01", code, language="powershell", args=["-Foo", "bar"], env_vars=["A=1"], timeout=90, confirm=True
    )
    body = json.loads(route.calls.last.request.content)
    assert body == {"code": code, "shell": "powershell", "args": ["-Foo", "bar"], "env_vars": ["A=1"], "timeout": 90, "run_as_user": False}
    assert r["result"]["retcode"] == 0


async def test_preview_shows_env_names_only(agents):
    r = await tools_exec.trmm_run_script_code("PC-OFFICE01", "echo %A%", language="cmd", env_vars=["A=geheim"])
    assert r["env_var_names"] == ["A"]
    assert "geheim" not in json.dumps(r)


def test_audit_log_redacts_env_args_and_command():
    from tactical_mcp import guard

    params = {
        "agent": "pc1",
        "command": "net user admin Password=Geheim123 /add",
        "code": "x" * 500,
        "args": ["-p", "secret1", "--password=xyz", "-v"],
        "env_vars": ["ADMIN_PW=abc", "X=1"],
        "api_token": "zzz",
        "note": "Konto angelegt, token: abc123",
    }
    out = guard.redact_params(params)
    text = json.dumps(out)
    for secret in ("Geheim123", "secret1", "xyz", "abc", "zzz", "abc123"):
        assert secret not in text
    assert out["env_vars"] == ["ADMIN_PW", "X"]
    assert out["args"] == ["-p", "***", "--password=***", "-v"]
    assert out["api_token"] == "***"
    assert len(out["code"]) < 300 and "gekürzt" in out["code"]
    assert out["agent"] == "pc1"


async def test_audit_log_line_without_env_values(agents, capsys):
    agents.post(f"/scripts/{WIN_ID}/test/").respond(200, json={"stdout": "", "stderr": "", "retcode": 0})
    from tactical_mcp.app import mcp

    await mcp.call_tool("trmm_run_script_code", {
        "agent": "PC-OFFICE01", "code": "echo %A%", "language": "cmd", "env_vars": ["A=streng-geheim"],
        "args": ["--password", "pw-geheim"], "confirm": True,
    })
    log = capsys.readouterr().out
    assert "trmm_run_script_code" in log
    assert "streng-geheim" not in log and "pw-geheim" not in log
    assert '"env_vars": ["A"]' in log


async def test_run_saved_script_by_name(agents):
    agents.get("/scripts/").respond(200, json=[{"id": 7, "name": "Clear Print Spooler"}, {"id": 8, "name": "Other"}])
    agents.get("/scripts/7/").respond(200, json={
        "id": 7, "name": "Clear Print Spooler", "shell": "powershell", "args": [], "env_vars": [],
        "default_timeout": 90, "script_body": "Restart-Service Spooler",
    })
    route = agents.post(f"/agents/{WIN_ID}/runscript/").respond(200, json="done")
    r = await tools_exec.trmm_run_script("PC-OFFICE01", script_name="clear print spooler", confirm=True)
    body = json.loads(route.calls.last.request.content)
    assert body["script"] == 7 and body["output"] == "wait" and body["timeout"] == 90
    assert r["result"] == "done"


async def test_saved_script_body_is_checked(agents):
    agents.get("/scripts/9/").respond(200, json={"id": 9, "name": "Wipe", "shell": "cmd", "script_body": "format D: /q"})
    with pytest.raises(GuardError, match="blockiert"):
        await tools_exec.trmm_run_script("PC-OFFICE01", script_id=9, confirm=True)
    assert written(agents) == []


async def test_ambiguous_hostname(mock):
    a = {"hostname": "PC1", "agent_id": "A" * 40, "client_name": "X", "site_name": "1", "status": "online"}
    b = {"hostname": "pc1", "agent_id": "B" * 40, "client_name": "Y", "site_name": "2", "status": "online"}
    mock.get("/agents/").respond(200, json=[a, b])
    with pytest.raises(GuardError, match="mehrdeutig"):
        await app.resolve_agent("PC1")
    assert (await app.resolve_agent("B" * 40))["client_name"] == "Y"


async def test_unknown_agent(agents):
    with pytest.raises(GuardError, match="Kein Agent"):
        await app.resolve_agent("gibtsnicht")


async def test_partial_hostname_unique(agents):
    assert (await app.resolve_agent("office01"))["agent_id"] == WIN_ID


async def test_write_timeout_is_unclear_state(agents):
    agents.post(f"/agents/{WIN_ID}/cmd/").mock(side_effect=httpx.ReadTimeout("x"))
    with pytest.raises(UnclearStateError, match="unklar"):
        await tools_exec.trmm_run_command("PC-OFFICE01", "whoami", confirm=True)


async def test_api_key_header_and_redaction(agents):
    route = agents.get(f"/agents/{WIN_ID}/notes/").respond(200, json=[{"pk": 1, "note": f"key {TRMM_KEY}", "username": "x"}])
    from tactical_mcp.app import mcp

    result = await mcp.call_tool("trmm_get_agent_notes", {"agent": "PC-OFFICE01"})
    assert route.calls.last.request.headers["X-API-KEY"] == TRMM_KEY
    text = json.dumps(result, default=str)
    assert TRMM_KEY not in text and "***" in text


async def test_error_messages_without_key(agents):
    agents.get(f"/agents/{WIN_ID}/").respond(403, json={"detail": "nope"})
    from mcp.server.mcpserver.exceptions import ToolError
    from tactical_mcp.app import mcp

    with pytest.raises(ToolError) as ei:
        await mcp.call_tool("trmm_get_agent", {"agent": "PC-OFFICE01"})
    assert "403" in str(ei.value) and TRMM_KEY not in str(ei.value)


async def test_list_agents_filters(agents):
    r = await tools_read.trmm_list_agents(client_name="example", status="online")
    assert {a["hostname"] for a in r["agents"]} == {"PC-OFFICE01", "nas-backup"}
    r = await tools_read.trmm_list_agents(search="anna")
    assert [a["hostname"] for a in r["agents"]] == ["PC-OFFICE01"]


async def test_event_log_filter(agents):
    agents.get(f"/agents/{WIN_ID}/eventlog/System/2/").respond(200, json=[
        {"time": "2026-10-17 10:00", "eventType": "ERROR", "source": "Disk", "message": "Fehler"},
        {"time": "2026-10-17 11:00", "eventType": "INFO", "source": "Kernel", "message": "ok"},
    ])
    r = await tools_read.trmm_get_event_log("PC-OFFICE01", log="System", days=2, level="error")
    assert r["count"] == 1 and r["events"][0]["source"] == "Disk"


async def test_alert_action_preview_and_execute(agents):
    agents.get("/alerts/5/").respond(200, json={"id": 5, "hostname": "PC-OFFICE01", "agent_id": WIN_ID, "severity": "error"})
    route = agents.put("/alerts/5/").respond(200, json="ok")
    p = await tools_exec.trmm_alert_action(5, "snooze", snooze_days=3)
    assert p["preview"] is True and not route.called
    await tools_exec.trmm_alert_action(5, "snooze", snooze_days=3, confirm=True)
    assert json.loads(route.calls.last.request.content) == {"type": "snooze", "snooze_days": 3}
