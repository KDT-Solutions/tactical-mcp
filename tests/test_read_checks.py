"""trmm_get_agent_checks: eingestellter vs. aktueller Schweregrad."""

from conftest import LIN_ID

from tactical_mcp import tools_read

CHECKS = [
    {"id": 1, "readable_desc": "Script Check: Health", "check_type": "script", "alert_severity": "error",
     "check_result": {"status": "passing", "alert_severity": "warning", "retcode": 0, "stdout": "OK"}},
    {"id": 2, "readable_desc": "Script Check: Disk", "check_type": "script", "alert_severity": "error",
     "check_result": {"status": "failing", "alert_severity": "warning", "retcode": 1, "stdout": "WARNUNG"}},
]


async def test_checks_show_configured_and_current_severity(agents):
    agents.get(f"/agents/{LIN_ID}/checks/").respond(200, json=CHECKS)
    r = await tools_read.trmm_get_agent_checks("nas-backup")
    ok, warn = r["checks"]
    assert ok["alert_severity"] == "error" and "current_severity" not in ok
    assert warn["alert_severity"] == "error" and warn["current_severity"] == "warning"


async def test_checks_only_failing(agents):
    agents.get(f"/agents/{LIN_ID}/checks/").respond(200, json=CHECKS)
    r = await tools_read.trmm_get_agent_checks("nas-backup", only_failing=True)
    assert [c["id"] for c in r["checks"]] == [2]
