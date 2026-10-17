"""confirm-Logik, Schutzlisten, gesperrte Befehle, Nur-Lese-Modus, Plattform-Prüfung."""

import pytest

from conftest import DC_ID, LIN_ID, WIN_ID, written
from tactical_mcp import config, tools_exec
from tactical_mcp.errors import GuardError


async def test_preview_without_confirm_sends_nothing(agents):
    r = await tools_exec.trmm_run_command("PC-OFFICE01", "Get-Service spooler", shell="powershell")
    assert r["preview"] is True and r["executed"] is False
    assert r["agent"]["hostname"] == "PC-OFFICE01"
    assert r["command"] == "Get-Service spooler"
    assert written(agents) == []


async def test_run_command_with_confirm(agents):
    route = agents.post(f"/agents/{WIN_ID}/cmd/").respond(200, json="Running")
    r = await tools_exec.trmm_run_command("pc-office01", "Get-Service spooler", shell="PowerShell", timeout=30, confirm=True)
    assert r["executed"] is True and r["result"] == "Running"
    import json

    body = json.loads(route.calls.last.request.content)
    assert body == {"shell": "powershell", "cmd": "Get-Service spooler", "timeout": 30, "custom_shell": None, "run_as_user": False}


async def test_bash_maps_to_bin_bash_on_linux(agents):
    route = agents.post(f"/agents/{LIN_ID}/cmd/").respond(200, json="ok")
    await tools_exec.trmm_run_command("nas-backup", "uptime", shell="bash", confirm=True)
    import json

    assert json.loads(route.calls.last.request.content)["shell"] == "/bin/bash"


@pytest.mark.parametrize("agent,shell", [("PC-OFFICE01", "bash"), ("nas-backup", "powershell"), ("nas-backup", "cmd")])
async def test_shell_platform_mismatch(agents, agent, shell):
    with pytest.raises(GuardError):
        await tools_exec.trmm_run_command(agent, "whoami", shell=shell, confirm=True)
    assert written(agents) == []


async def test_protected_agent_blocked(agents):
    with pytest.raises(GuardError, match="geschützt"):
        await tools_exec.trmm_run_command("SRV-DC01", "whoami", confirm=True)
    with pytest.raises(GuardError, match="geschützt"):
        await tools_exec.trmm_reboot_agent(DC_ID, confirm=True)
    assert written(agents) == []


async def test_offline_agent_refused(agents):
    with pytest.raises(GuardError, match="nicht online"):
        await tools_exec.trmm_run_command("PC-LAGER", "whoami", confirm=True)


@pytest.mark.parametrize("cmd", [
    "format C: /q",
    "Format-Volume -DriveLetter D",
    "diskpart /s wipe.txt",
    "vssadmin delete shadows /all /quiet",
    "cipher /w:C:\\",
    "Remove-Item -Recurse -Force C:\\",
    "rd /s /q C:\\",
    "bcdedit /delete {current}",
    "Clear-Disk -Number 0 -RemoveData",
    '"C:\\Program Files\\TacticalAgent\\unins000.exe" /VERYSILENT',
    "sc delete tacticalrmm",
])
async def test_blocked_commands(agents, cmd):
    with pytest.raises(GuardError, match="blockiert"):
        await tools_exec.trmm_run_command("PC-OFFICE01", cmd, shell="cmd", confirm=True)
    assert written(agents) == []


@pytest.mark.parametrize("cmd", [
    "Remove-Item -Recurse -Force C:\\Temp\\old",
    "Get-ChildItem C:\\ | Format-Table",
    "rd /s /q C:\\Windows\\Temp\\x",
    "ipconfig /all",
])
async def test_legit_commands_not_blocked(agents, cmd):
    r = await tools_exec.trmm_run_command("PC-OFFICE01", cmd, shell="cmd")
    assert r["preview"] is True


async def test_blocked_in_multiline_script(agents):
    code = "Write-Host 'Aufräumen'\nvssadmin delete shadows /all /quiet\n"
    with pytest.raises(GuardError, match="blockiert"):
        await tools_exec.trmm_run_script_code("PC-OFFICE01", code, confirm=True)


async def test_extra_blocked_patterns(agents, monkeypatch):
    monkeypatch.setenv("BLOCKED_COMMAND_PATTERNS", r"\bnet\s+user\b;;\bStop-Computer\b")
    config.reset()
    with pytest.raises(GuardError, match="blockiert"):
        await tools_exec.trmm_run_command("PC-OFFICE01", "net user admin x", shell="cmd")
    with pytest.raises(GuardError, match="blockiert"):
        await tools_exec.trmm_run_command("PC-OFFICE01", "Stop-Computer -Force")


async def test_read_only_blocks_everything(agents, monkeypatch):
    monkeypatch.setenv("TRMM_READ_ONLY", "1")
    config.reset()
    for call in (
        tools_exec.trmm_run_command("PC-OFFICE01", "whoami"),
        tools_exec.trmm_reboot_agent("PC-OFFICE01"),
        tools_exec.trmm_add_agent_note("PC-OFFICE01", "x"),
        tools_exec.trmm_alert_action(1, "resolve"),
    ):
        with pytest.raises(GuardError, match="Nur-Lese"):
            await call
    assert written(agents) == []


async def test_timeout_bounds(agents):
    with pytest.raises(GuardError, match="timeout"):
        await tools_exec.trmm_run_command("PC-OFFICE01", "whoami", timeout=5000)
    with pytest.raises(GuardError, match="timeout"):
        await tools_exec.trmm_run_command("PC-OFFICE01", "whoami", timeout=1)


async def test_agent_service_not_stoppable(agents):
    with pytest.raises(GuardError, match="Agent-Dienst"):
        await tools_exec.trmm_service_action("PC-OFFICE01", "tacticalrmm", "stop", confirm=True)
    assert written(agents) == []


async def test_service_restart(agents):
    route = agents.post(f"/services/{WIN_ID}/Spooler/").respond(200, json="The service was restarted successfully")
    r = await tools_exec.trmm_service_action("PC-OFFICE01", "Spooler", "restart", confirm=True)
    import json

    assert json.loads(route.calls.last.request.content) == {"sv_action": "restart"}
    assert r["executed"] is True


async def test_kill_agent_process_blocked(agents):
    agents.get(f"/agents/{WIN_ID}/processes/").respond(200, json=[{"pid": 42, "name": "tacticalrmm.exe"}])
    with pytest.raises(GuardError):
        await tools_exec.trmm_kill_process("PC-OFFICE01", 42, confirm=True)
