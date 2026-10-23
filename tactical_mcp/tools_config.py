"""Konfigurierende Tools: Scripts in der Bibliothek anlegen/ändern, Checks und
automatisierte Tasks auf Agents oder Policies anlegen, Policies auflisten.

Gleiche Regeln wie in tools_exec: TRMM_READ_ONLY sperrt alles, geschützte Agents
werden blockiert, ohne confirm=true nur Vorschau, Script-Code läuft durch die
Sperrliste. Gelöscht wird nichts.
"""

from __future__ import annotations

from typing import Any

from . import guard
from .app import agent_label, resolve_agent, tool, trmm
from .errors import GuardError

PLATFORMS = {"windows", "linux", "darwin"}
SEVERITIES = {"info", "warning", "error"}


def _platforms(values: list[str] | None) -> list[str]:
    out = [p.strip().lower() for p in (values or []) if p and p.strip()]
    bad = [p for p in out if p not in PLATFORMS]
    if bad:
        raise GuardError(f"Ungültige Plattform(en) {bad}. Erlaubt: windows, linux, darwin.")
    return out


def _codes(values: list[int] | None, label: str) -> list[int]:
    out = []
    for v in values or []:
        try:
            out.append(int(v))
        except (TypeError, ValueError) as exc:
            raise GuardError(f"{label}: {v!r} ist keine Zahl.") from exc
    return out


async def _target_agent(agent: str) -> dict[str, Any]:
    guard.require_writable()
    a = await resolve_agent(agent)
    guard.check_agent_allowed(a)
    return a


# ---------------------------------------------------------------------------
# Script-Bibliothek
# ---------------------------------------------------------------------------


@tool()
async def trmm_save_script(
    name: str,
    code: str,
    language: str = "shell",
    script_id: int = 0,
    category: str = "",
    description: str = "",
    platforms: list[str] | None = None,
    args: list[str] | None = None,
    default_timeout: int = 60,
    run_as_user: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Script in der Tactical-Bibliothek anlegen (script_id=0) oder ändern (script_id>0).

    language: powershell, cmd, python, shell, nushell, deno. platforms: windows, linux, darwin.
    Der Code läuft durch die Sperrliste. Ohne confirm=true nur Vorschau."""
    guard.require_writable()
    lang = guard.validate_script_shell(language)
    if not (name or "").strip():
        raise GuardError("name ist leer.")
    body = code or ""
    if not body.strip():
        raise GuardError("code ist leer.")
    arg_list = guard.validate_str_list(args, "args")
    guard.check_command_allowed(body, " ".join(arg_list))
    plats = _platforms(platforms)
    t = guard.validate_timeout(default_timeout, 60)
    payload = {
        "name": name.strip(), "shell": lang, "category": category.strip(), "description": description.strip(),
        "script_body": body, "args": arg_list, "env_vars": [], "default_timeout": t,
        "supported_platforms": plats, "run_as_user": bool(run_as_user),
    }
    sid = int(script_id or 0)
    existing = None
    if sid:
        sid = guard.validate_positive_int(sid, "script_id")
        existing = await trmm().get(f"/scripts/{sid}/") or {}
        if existing.get("script_type") == "builtin":
            raise GuardError("Community-Scripts werden nicht geändert. Neues Script anlegen (script_id=0).")
    if not confirm:
        return guard.preview(
            "save_script", mode="update" if sid else "create", script_id=sid or None,
            previous_name=(existing or {}).get("name"), **{**payload, "script_body": guard.truncate(body, 8000)},
        )
    if sid:
        r = await trmm().put(f"/scripts/{sid}/", json=payload)
    else:
        r = await trmm().post("/scripts/", json=payload)
    return {"executed": True, "action": "save_script", "mode": "update" if sid else "create", "result": guard.truncate(r)}


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@tool()
async def trmm_list_policies() -> list[dict[str, Any]]:
    """Automation-Policies mit ID, Name, aktiv/inaktiv und Beschreibung."""
    ps = await trmm().get("/automation/policies/") or []
    return [{k: p.get(k) for k in ("id", "name", "desc", "active", "enforced")} for p in ps]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@tool()
async def trmm_add_script_check(
    script_id: int,
    agent: str = "",
    policy_id: int = 0,
    run_interval_minutes: int = 30,
    timeout: int = 60,
    args: list[str] | None = None,
    warning_return_codes: list[int] | None = None,
    info_return_codes: list[int] | None = None,
    alert_severity: str = "error",
    fails_before_alert: int = 1,
    confirm: bool = False,
) -> dict[str, Any]:
    """Script Check auf einem Agent ODER in einer Policy anlegen.

    Exit 0 = bestanden, Codes in warning_return_codes/info_return_codes = Warnung/Info, sonst Fehler.
    Ohne confirm=true nur Vorschau."""
    guard.require_writable()
    if bool(agent.strip()) == bool(policy_id):
        raise GuardError("Genau eines angeben: agent oder policy_id.")
    sid = guard.validate_positive_int(script_id, "script_id")
    s = await trmm().get(f"/scripts/{sid}/") or {}
    arg_list = guard.validate_str_list(args, "args")
    guard.check_command_allowed(str(s.get("script_body", "")), " ".join(arg_list))
    sev = (alert_severity or "").strip().lower()
    if sev not in SEVERITIES:
        raise GuardError("alert_severity muss info, warning oder error sein.")
    interval = int(run_interval_minutes)
    if not 1 <= interval <= 1440:
        raise GuardError("run_interval_minutes muss zwischen 1 und 1440 liegen.")
    payload: dict[str, Any] = {
        "check_type": "script", "script": sid, "script_args": arg_list, "env_vars": [],
        "timeout": guard.validate_timeout(timeout, 60), "run_interval": interval * 60,
        "warning_return_codes": _codes(warning_return_codes, "warning_return_codes"),
        "info_return_codes": _codes(info_return_codes, "info_return_codes"),
        "alert_severity": sev, "fails_b4_alert": max(1, int(fails_before_alert)),
        "dashboard_alert": True, "email_alert": False, "text_alert": False,
    }
    target: dict[str, Any]
    if agent.strip():
        a = await _target_agent(agent)
        payload["agent"] = a["agent_id"]
        target = {"agent": agent_label(a)}
    else:
        pid = guard.validate_positive_int(policy_id, "policy_id")
        payload["policy"] = pid
        target = {"policy_id": pid}
    if not confirm:
        return guard.preview("add_script_check", **target, script_name=s.get("name"), **payload)
    r = await trmm().post("/checks/", json=payload)
    return {"executed": True, "action": "add_script_check", **target, "script_name": s.get("name"), "result": guard.truncate(r)}


# ---------------------------------------------------------------------------
# Automatisierte Tasks
# ---------------------------------------------------------------------------


@tool()
async def trmm_add_monthly_script_task(
    name: str,
    script_id: int,
    day_of_month: int,
    time_hhmm: str,
    agent: str = "",
    policy_id: int = 0,
    args: list[str] | None = None,
    timeout: int = 3600,
    confirm: bool = False,
) -> dict[str, Any]:
    """Monatlichen Task anlegen, der ein Bibliotheks-Script ausführt (auf Agent ODER Policy).

    day_of_month: 1-31, time_hhmm: z.B. "02:30" (Zeit des Agents). Ohne confirm=true nur Vorschau.
    Hinweis: Feldnamen für task_type=monthly vor dem ersten Einsatz gegen die eigene
    Tactical-Version prüfen (API-Schema), sie haben sich zwischen Versionen geändert."""
    guard.require_writable()
    if bool(agent.strip()) == bool(policy_id):
        raise GuardError("Genau eines angeben: agent oder policy_id.")
    if not (name or "").strip():
        raise GuardError("name ist leer.")
    sid = guard.validate_positive_int(script_id, "script_id")
    s = await trmm().get(f"/scripts/{sid}/") or {}
    arg_list = guard.validate_str_list(args, "args")
    guard.check_command_allowed(str(s.get("script_body", "")), " ".join(arg_list))
    day = int(day_of_month)
    if not 1 <= day <= 31:
        raise GuardError("day_of_month muss zwischen 1 und 31 liegen.")
    try:
        hh, mm = (int(x) for x in time_hhmm.split(":"))
        assert 0 <= hh <= 23 and 0 <= mm <= 59
    except Exception as exc:  # noqa: BLE001
        raise GuardError("time_hhmm im Format HH:MM angeben, z.B. 02:30.") from exc
    t = guard.validate_timeout(timeout, 3600)
    payload: dict[str, Any] = {
        "name": name.strip(), "task_type": "monthly", "enabled": True,
        "run_time_date": f"2026-01-01T{hh:02d}:{mm:02d}:00",
        "monthly_days_of_month": 1 << (day - 1), "monthly_months_of_year": 4095,
        "task_instance_policy": 0, "alert_severity": "warning", "dashboard_alert": True,
        "actions": [{"type": "script", "script": sid, "name": s.get("name"), "timeout": t,
                     "script_args": arg_list, "env_vars": []}],
    }
    if agent.strip():
        a = await _target_agent(agent)
        payload["agent"] = a["agent_id"]
        target = {"agent": agent_label(a)}
    else:
        payload["policy"] = guard.validate_positive_int(policy_id, "policy_id")
        target = {"policy_id": payload["policy"]}
    if not confirm:
        return guard.preview("add_monthly_script_task", **target, script_name=s.get("name"), **payload)
    r = await trmm().post("/tasks/", json=payload)
    return {"executed": True, "action": "add_monthly_script_task", **target, "result": guard.truncate(r)}
