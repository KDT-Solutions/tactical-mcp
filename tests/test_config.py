"""Konfigurierende Tools: Script-Bibliothek, Policies, Script Checks, monatliche Tasks."""

import json

import pytest
from conftest import DC_ID, WIN_ID, written

from tactical_mcp import tools_config
from tactical_mcp.errors import GuardError

SCRIPT = {"id": 7, "name": "Disk Check", "shell": "powershell", "script_type": "userdefined",
          "script_body": "Get-PSDrive C"}


@pytest.fixture
def script(agents):
    agents.get("/scripts/7/").respond(200, json=SCRIPT)
    return agents


# ---------------------------------------------------------------------------
# trmm_save_script
# ---------------------------------------------------------------------------


async def test_save_script_preview_writes_nothing(mock):
    r = await tools_config.trmm_save_script("Test", "echo hi", language="shell", platforms=["Linux"])
    assert r["preview"] is True and r["mode"] == "create"
    assert r["supported_platforms"] == ["linux"]
    assert written(mock) == []


async def test_save_script_create(mock):
    route = mock.post("/scripts/").respond(200, json="ok")
    r = await tools_config.trmm_save_script(
        " Test ", "echo hi", language="Shell", category="Wartung", args=["-a"], default_timeout=120, confirm=True
    )
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "name": "Test", "shell": "shell", "category": "Wartung", "description": "", "script_body": "echo hi",
        "args": ["-a"], "env_vars": [], "default_timeout": 120, "supported_platforms": [], "run_as_user": False,
    }
    assert r["executed"] is True and r["mode"] == "create"


async def test_save_script_update(script):
    route = script.put("/scripts/7/").respond(200, json="ok")
    r = await tools_config.trmm_save_script("Disk Check", "Get-PSDrive D", language="powershell", script_id=7, confirm=True)
    assert json.loads(route.calls.last.request.content)["script_body"] == "Get-PSDrive D"
    assert r["mode"] == "update"


async def test_save_script_refuses_community_script(mock):
    mock.get("/scripts/3/").respond(200, json={"id": 3, "name": "Community", "script_type": "builtin"})
    with pytest.raises(GuardError, match="Community"):
        await tools_config.trmm_save_script("x", "echo hi", script_id=3, confirm=True)
    assert written(mock) == []


async def test_save_script_blocked_code(mock):
    with pytest.raises(GuardError, match="blockiert"):
        await tools_config.trmm_save_script("Wipe", "format D: /q", language="cmd", confirm=True)
    assert written(mock) == []


@pytest.mark.parametrize("kwargs, msg", [
    ({"name": " ", "code": "echo"}, "name"),
    ({"name": "x", "code": "  "}, "code"),
    ({"name": "x", "code": "echo", "language": "ruby"}, "Script-Sprache"),
    ({"name": "x", "code": "echo", "platforms": ["bsd"]}, "Plattform"),
])
async def test_save_script_validation(mock, kwargs, msg):
    with pytest.raises(GuardError, match=msg):
        await tools_config.trmm_save_script(**kwargs, confirm=True)


async def test_save_script_read_only(mock, monkeypatch):
    from tactical_mcp import config

    monkeypatch.setenv("TRMM_READ_ONLY", "1")
    config.reset()
    with pytest.raises(GuardError):
        await tools_config.trmm_save_script("x", "echo hi", confirm=True)
    assert written(mock) == []


# ---------------------------------------------------------------------------
# trmm_list_policies
# ---------------------------------------------------------------------------


async def test_list_policies(mock):
    mock.get("/automation/policies/").respond(200, json=[
        {"id": 1, "name": "Server", "desc": "Basis", "active": True, "enforced": False, "agents_count": 4},
    ])
    assert await tools_config.trmm_list_policies() == [
        {"id": 1, "name": "Server", "desc": "Basis", "active": True, "enforced": False},
    ]


# ---------------------------------------------------------------------------
# trmm_add_script_check
# ---------------------------------------------------------------------------


async def test_script_check_on_agent(script):
    route = script.post("/checks/").respond(200, json="ok")
    r = await tools_config.trmm_add_script_check(
        7, agent="PC-OFFICE01", run_interval_minutes=15, warning_return_codes=[2, "3"], alert_severity="Warning",
        fails_before_alert=0, confirm=True,
    )
    body = json.loads(route.calls.last.request.content)
    assert body["agent"] == WIN_ID and "policy" not in body
    assert body["script"] == 7 and body["run_interval"] == 900
    assert body["warning_return_codes"] == [2, 3] and body["alert_severity"] == "warning"
    assert body["fails_b4_alert"] == 1
    assert r["executed"] is True and r["script_name"] == "Disk Check"


async def test_script_check_on_policy(script):
    route = script.post("/checks/").respond(200, json="ok")
    await tools_config.trmm_add_script_check(7, policy_id=4, confirm=True)
    body = json.loads(route.calls.last.request.content)
    assert body["policy"] == 4 and "agent" not in body


async def test_script_check_preview(script):
    r = await tools_config.trmm_add_script_check(7, agent="PC-OFFICE01")
    assert r["preview"] is True and r["agent"]["hostname"] == "PC-OFFICE01"
    assert written(script) == []


async def test_monthly_task_preview_on_agent(script):
    r = await tools_config.trmm_add_monthly_script_task("Monatscheck", 7, 1, "02:00", agent="PC-OFFICE01")
    assert r["preview"] is True and r["agent"]["hostname"] == "PC-OFFICE01"
    assert written(script) == []


@pytest.mark.parametrize("kwargs, msg", [
    ({}, "Genau eines"),
    ({"agent": "PC-OFFICE01", "policy_id": 4}, "Genau eines"),
    ({"agent": "PC-OFFICE01", "alert_severity": "fatal"}, "alert_severity"),
    ({"agent": "PC-OFFICE01", "run_interval_minutes": 0}, "run_interval_minutes"),
    ({"agent": "PC-OFFICE01", "info_return_codes": ["x"]}, "keine Zahl"),
])
async def test_script_check_validation(script, kwargs, msg):
    with pytest.raises(GuardError, match=msg):
        await tools_config.trmm_add_script_check(7, **kwargs, confirm=True)
    assert written(script) == []


async def test_script_check_protected_agent(script):
    with pytest.raises(GuardError):
        await tools_config.trmm_add_script_check(7, agent=DC_ID, confirm=True)
    assert written(script) == []


async def test_script_check_blocked_script(agents):
    agents.get("/scripts/9/").respond(200, json={"id": 9, "name": "Wipe", "script_body": "format D: /q"})
    with pytest.raises(GuardError, match="blockiert"):
        await tools_config.trmm_add_script_check(9, agent="PC-OFFICE01", confirm=True)
    assert written(agents) == []


# ---------------------------------------------------------------------------
# trmm_add_monthly_script_task
# ---------------------------------------------------------------------------


async def test_monthly_task_on_agent(script):
    route = script.post("/tasks/").respond(200, json="ok")
    r = await tools_config.trmm_add_monthly_script_task(
        "Monatscheck", 7, day_of_month=15, time_hhmm="02:30", agent="PC-OFFICE01", args=["-v"], confirm=True
    )
    body = json.loads(route.calls.last.request.content)
    assert body["agent"] == WIN_ID and body["task_type"] == "monthly"
    assert body["run_time_date"].endswith("T02:30:00")
    assert body["monthly_days_of_month"] == 1 << 14 and body["monthly_months_of_year"] == 4095
    assert body["actions"] == [{"type": "script", "script": 7, "name": "Disk Check", "timeout": 600,
                                "script_args": ["-v"], "env_vars": []}]
    assert r["executed"] is True


async def test_monthly_task_on_policy_preview(script):
    r = await tools_config.trmm_add_monthly_script_task("Monatscheck", 7, 31, "23:59", policy_id=2)
    assert r["preview"] is True and r["policy_id"] == 2 and r["monthly_days_of_month"] == 1 << 30
    assert written(script) == []


@pytest.mark.parametrize("time_hhmm", ["25:00", "12:60", "-1:00", "2", "02:30:00", "ab:cd", ""])
async def test_monthly_task_invalid_time(script, time_hhmm):
    with pytest.raises(GuardError, match="HH:MM"):
        await tools_config.trmm_add_monthly_script_task("x", 7, 1, time_hhmm, agent="PC-OFFICE01", confirm=True)
    assert written(script) == []


@pytest.mark.parametrize("day", [0, 32])
async def test_monthly_task_invalid_day(script, day):
    with pytest.raises(GuardError, match="day_of_month"):
        await tools_config.trmm_add_monthly_script_task("x", 7, day, "02:00", agent="PC-OFFICE01", confirm=True)


async def test_monthly_task_needs_exactly_one_target(script):
    with pytest.raises(GuardError, match="Genau eines"):
        await tools_config.trmm_add_monthly_script_task("x", 7, 1, "02:00", confirm=True)
