"""Konfigurierende Tools: Scripts in der Bibliothek anlegen, Checks und
automatisierte Tasks auf Agents oder Policies anlegen, Policies auflisten.

Gleiche Regeln wie in tools_exec: TRMM_READ_ONLY sperrt alles, geschützte Agents
werden blockiert (auch über Policies, siehe _check_policy_allowed), ohne
confirm=true nur Vorschau, Script-Code läuft durch die Sperrliste, alles braucht
MCP_ALLOW_EXEC=1. Bestehende Scripts werden nicht geändert und nichts gelöscht.
"""

from __future__ import annotations

from typing import Any

from . import guard
from .app import agent_label, list_agents_brief, resolve_agent, tool, trmm
from .config import settings
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
    guard.require_exec()
    a = await resolve_agent(agent)
    guard.check_agent_allowed(a)
    return a


def _same(a: Any, b: Any) -> bool:
    return str(a or "").strip().lower() == str(b or "").strip().lower()


async def policy_agents(policy_id: int) -> list[dict[str, Any]]:
    """Agents, auf denen eine Policy (mindestens) wirkt - bewusst grosszügig:
    direkt zugewiesene Agents, alle Agents der zugewiesenen Sites und Clients
    (nach Server/Workstation) und bei Default-Policies alle Agents des Typs.
    Vererbungs-Ausnahmen (block_policy_inheritance) werden ignoriert, damit im
    Zweifel zu viele und nicht zu wenige Agents geschützt sind.
    Endpunkt: GET /automation/policies/<id>/related/ (Felder agents,
    server_clients, workstation_clients, server_sites, workstation_sites,
    default_server_policy, default_workstation_policy)."""
    rel = await trmm().get(f"/automation/policies/{policy_id}/related/")
    if not isinstance(rel, dict):
        raise GuardError(f"Zuordnung der Policy {policy_id} konnte nicht gelesen werden (unerwartete Antwort).")
    agents = await list_agents_brief()
    out: dict[str, dict[str, Any]] = {}

    def add(a: dict[str, Any]) -> None:
        out[str(a.get("agent_id") or a.get("id") or a.get("hostname"))] = a

    direct = rel.get("agents") or []
    for d in direct:
        for a in agents:
            if (d.get("agent_id") and _same(d.get("agent_id"), a.get("agent_id"))) or (
                d.get("id") is not None and str(d.get("id")) == str(a.get("id"))
            ) or (d.get("hostname") and _same(d.get("hostname"), a.get("hostname"))):
                add(a)
    for kind in ("server", "workstation"):
        clients = {str(c.get("name", "")).lower() for c in (rel.get(f"{kind}_clients") or [])}
        sites = {
            (str(sx.get("client_name", "")).lower() or None, str(sx.get("name", "")).lower())
            for sx in (rel.get(f"{kind}_sites") or [])
        }
        default = bool(rel.get(f"default_{kind}_policy"))
        for a in agents:
            if not _same(a.get("monitoring_type"), kind):
                continue
            cname = str(a.get("client_name", "")).lower()
            sname = str(a.get("site_name", "")).lower()
            if default or cname in clients or (cname, sname) in sites or (None, sname) in sites:
                add(a)
    return list(out.values())


async def _check_policy_allowed(policy_id: int) -> dict[str, Any]:
    """Policy-Ziel: ablehnen, wenn ein geschützter Agent von der Policy betroffen wäre.
    Lässt sich die Zuordnung nicht lesen (z.B. fehlendes Recht), wird abgelehnt."""
    pid = guard.validate_positive_int(policy_id, "policy_id")
    if not settings().protected_agents:
        return {"policy_id": pid}
    try:
        affected = await policy_agents(pid)
    except GuardError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail closed, Details im Log
        raise GuardError(
            f"Zuordnung der Policy {pid} konnte nicht geprüft werden ({type(exc).__name__}); "
            "wegen PROTECTED_AGENTS wird das Policy-Ziel abgelehnt. Stattdessen einzelne Agents angeben."
        ) from None
    blocked = [a for a in affected if guard.agent_protection(a.get("hostname", ""), a.get("agent_id", ""))]
    if blocked:
        names = ", ".join(sorted(str(a.get("hostname")) for a in blocked)[:20])
        raise GuardError(
            f"Policy {pid} wirkt auf geschützte Agents ({names}, PROTECTED_AGENTS). "
            "Checks/Tasks darauf nur direkt in Tactical oder auf einzelnen, nicht geschützten Agents anlegen."
        )
    return {"policy_id": pid, "policy_agents": len(affected)}


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
    """Neues Script in der Tactical-Bibliothek anlegen.

    language: powershell, cmd, python, shell, nushell, deno. platforms: windows, linux, darwin.
    Der Code läuft durch die Sperrliste. Ohne confirm=true nur Vorschau. Braucht MCP_ALLOW_EXEC=1.
    default_timeout höchstens MAX_TASK_TIMEOUT (Standard 14400 s); direkt ausgeführt (trmm_run_script)
    gilt weiterhin MAX_TIMEOUT, dann timeout beim Aufruf angeben.
    Bestehende Scripts (script_id>0) werden bewusst nicht geändert: ein Script kann in Checks und
    Tasks geschützter Agents hängen, und ein Update würde dort unbemerkt anderen Code ausführen.
    Änderungen an bestehenden Scripts nur direkt in Tactical."""
    guard.require_exec()
    if script_id:
        raise GuardError(
            "Bestehende Scripts werden über tactical-mcp nicht geändert (script_id muss 0 sein). "
            "Neues Script anlegen oder die Änderung direkt in Tactical machen."
        )
    lang = guard.validate_script_shell(language)
    if not (name or "").strip():
        raise GuardError("name ist leer.")
    body = code or ""
    if not body.strip():
        raise GuardError("code ist leer.")
    arg_list = guard.validate_str_list(args, "args")
    guard.check_command_allowed(body, " ".join(arg_list))
    plats = _platforms(platforms)
    t = guard.validate_timeout(default_timeout, 60, settings().max_task_timeout)
    payload = {
        "name": name.strip(), "shell": lang, "category": category.strip(), "description": description.strip(),
        "script_body": body, "args": arg_list, "env_vars": [], "default_timeout": t,
        "supported_platforms": plats, "run_as_user": bool(run_as_user),
    }
    if not confirm:
        return guard.preview("save_script", mode="create", **{**payload, "script_body": guard.truncate(body, 8000)})
    r = await trmm().post("/scripts/", json=payload)
    return {"executed": True, "action": "save_script", "mode": "create", "result": guard.truncate(r)}


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
    Der Schweregrad eines Alarms ergibt sich bei Script Checks in Tactical aus dem Exit-Code
    (info/warning_return_codes bzw. sonst error); alert_severity wird am Check gespeichert.
    Ohne confirm=true nur Vorschau. Braucht MCP_ALLOW_EXEC=1. Policy-Ziele werden abgelehnt,
    wenn die Policy auf geschützte Agents wirkt."""
    guard.require_exec()
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
        target = await _check_policy_allowed(policy_id)
        payload["policy"] = target["policy_id"]
    if not confirm:
        return guard.preview("add_script_check", script_name=s.get("name"), **{**payload, **target})
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
    timeout: int = 600,
    confirm: bool = False,
) -> dict[str, Any]:
    """Monatlichen Task anlegen, der ein Bibliotheks-Script ausführt (auf Agent ODER Policy).

    Nur Windows-Agents: Der Tactical-Agent für Linux/macOS führt geplante Tasks nicht aus
    (Linux-Agents werden abgelehnt; in Policies wirkt der Task nur auf die Windows-Agents).

    day_of_month: 1-31, time_hhmm: z.B. "02:30" (Zeit des Agents). timeout höchstens MAX_TASK_TIMEOUT (Standard 14400 s).
    Ohne confirm=true nur Vorschau. Braucht MCP_ALLOW_EXEC=1. Policy-Ziele werden abgelehnt,
    wenn die Policy auf geschützte Agents wirkt.
    Hinweis: Feldnamen für task_type=monthly vor dem ersten Einsatz gegen die eigene
    Tactical-Version prüfen (API-Schema), sie haben sich zwischen Versionen geändert."""
    guard.require_exec()
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
        hh, mm = (int(x) for x in (time_hhmm or "").split(":"))
    except ValueError as exc:
        raise GuardError("time_hhmm im Format HH:MM angeben, z.B. 02:30.") from exc
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise GuardError("time_hhmm im Format HH:MM angeben, z.B. 02:30.")
    t = guard.validate_timeout(timeout, 600, settings().max_task_timeout)
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
        plat = str(a.get("plat") or "").lower()
        if plat != "windows":
            raise GuardError(
                f"Tactical führt geplante Tasks nur auf Windows-Agents aus; der {plat or 'unbekannte'}-Agent "
                "würde den Task als synchronisiert melden, aber nie starten. Zeitplan auf dem Gerät selbst "
                "einrichten (z.B. cron oder DSM-Aufgabenplanung)."
            )
        payload["agent"] = a["agent_id"]
        target = {"agent": agent_label(a)}
    else:
        target = await _check_policy_allowed(policy_id)
        payload["policy"] = target["policy_id"]
    if not confirm:
        return guard.preview("add_monthly_script_task", script_name=s.get("name"), **{**payload, **target})
    r = await trmm().post("/tasks/", json=payload)
    return {"executed": True, "action": "add_monthly_script_task", **target, "result": guard.truncate(r)}
