"""Lesende Tools: Clients, Agents, Inventar, Software, Dienste, Prozesse,
Eventlogs, Checks, Tasks, Windows-Updates, Alerts, Verlauf, Scripts."""

from __future__ import annotations

import datetime as dt
from typing import Any

from . import guard
from .app import agent_label, list_agents_brief, resolve_agent, tool, trmm
from .config import settings
from .errors import GuardError
from .version import version_info

AGENT_LIST_FIELDS = (
    "hostname", "agent_id", "client_name", "site_name", "status", "plat", "monitoring_type",
    "description", "logged_username", "last_seen", "boot_time", "needs_reboot", "maintenance_mode",
    "pending_actions_count", "has_patches_pending", "make_model", "serial_number", "local_ips",
)

AGENT_DETAIL_FIELDS = (
    "hostname", "agent_id", "client", "site_name", "status", "plat", "goarch", "version",
    "operating_system", "monitoring_type", "description", "make_model", "serial_number", "cpu_model",
    "total_ram", "graphics", "physical_disks", "local_ips", "public_ip", "logged_in_username",
    "last_logged_in_user", "last_seen", "boot_time", "timezone", "needs_reboot", "maintenance_mode",
    "patches_last_installed", "checks", "custom_fields", "applied_policies", "effective_patch_policy",
    "alert_template",
)


def _pick(obj: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {k: obj.get(k) for k in fields if k in obj}


def _limit(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    lim = max(1, min(int(limit or 100), 2000))
    return items[:lim], len(items) > lim


# ---------------------------------------------------------------------------
# Allgemein
# ---------------------------------------------------------------------------


@tool()
async def trmm_version() -> dict[str, Any]:
    """Version von tactical-mcp (Tag, Commit, Build-Zeit) und der Tactical-RMM-Instanz."""
    info = version_info()
    try:
        info["tactical_rmm_version"] = await trmm().get("/core/version/")
    except Exception as exc:  # noqa: BLE001
        info["tactical_rmm_version"] = f"nicht abrufbar ({guard.redact_text(str(exc))})"
    info["read_only"] = settings().read_only
    return info


@tool()
async def trmm_list_clients() -> list[dict[str, Any]]:
    """Alle Clients mit ihren Sites (IDs und Namen) und der Anzahl Agents pro Site."""
    clients = await trmm().get("/clients/") or []
    out = []
    for c in clients:
        out.append({
            "id": c.get("id"),
            "name": c.get("name"),
            "sites": [
                {"id": s.get("id"), "name": s.get("name"), "agent_count": s.get("agent_count")}
                for s in (c.get("sites") or [])
            ],
            "agent_count": c.get("agent_count"),
        })
    return out


@tool()
async def trmm_list_agents(
    client_name: str = "",
    site_name: str = "",
    search: str = "",
    status: str = "",
    monitoring_type: str = "",
    limit: int = 500,
) -> dict[str, Any]:
    """Agents auflisten, optional gefiltert.

    client_name/site_name: Teilstring, Gross-/Kleinschreibung egal.
    search: Teilstring in Hostname, Beschreibung, angemeldetem Benutzer, Modell, Seriennummer oder IP.
    status: online, offline oder overdue. monitoring_type: server oder workstation."""
    agents = await list_agents_brief()
    cn, sn, q, st, mt = (v.strip().lower() for v in (client_name, site_name, search, status, monitoring_type))

    def match(a: dict[str, Any]) -> bool:
        if cn and cn not in str(a.get("client_name", "")).lower():
            return False
        if sn and sn not in str(a.get("site_name", "")).lower():
            return False
        if st and st != str(a.get("status", "")).lower():
            return False
        if mt and mt != str(a.get("monitoring_type", "")).lower():
            return False
        if q:
            hay = " ".join(str(a.get(k, "")) for k in (
                "hostname", "description", "logged_username", "make_model", "serial_number", "local_ips",
            )).lower()
            if q not in hay:
                return False
        return True

    rows = [_pick(a, AGENT_LIST_FIELDS) for a in agents if match(a)]
    rows.sort(key=lambda r: (str(r.get("client_name")), str(r.get("site_name")), str(r.get("hostname")).lower()))
    items, truncated = _limit(rows, limit)
    return {"count": len(rows), "truncated": truncated, "agents": items}


@tool()
async def trmm_get_agent(agent: str, include: list[str] | None = None) -> dict[str, Any]:
    """Details zu einem Agent (Hostname oder Agent-ID): OS, Hardware, Disks, IPs, Benutzer,
    letzte Verbindung, Bootzeit, Reboot nötig, Checks-Zusammenfassung, Custom Fields, Policies.

    include: zusätzliche, grosse Abschnitte - "disks", "wmi" (WMI-Details), "services"."""
    a = await resolve_agent(agent)
    d = await trmm().get(f"/agents/{a['agent_id']}/") or {}
    out = _pick(d, AGENT_DETAIL_FIELDS)
    if isinstance(out.get("total_ram"), (int, float)):
        out["total_ram_gb"] = out.pop("total_ram")
    inc = {i.strip().lower() for i in (include or [])}
    if "disks" in inc:
        out["disks"] = d.get("disks")
    if "wmi" in inc:
        out["wmi_detail"] = d.get("wmi_detail")
    if "services" in inc:
        out["services"] = d.get("services")
    return out


@tool()
async def trmm_ping_agent(agent: str) -> dict[str, Any]:
    """Prüft, ob der Agent live antwortet (über NATS), unabhängig vom zuletzt gemeldeten Status."""
    a = await resolve_agent(agent)
    r = await trmm().get(f"/agents/{a['agent_id']}/ping/", timeout=30)
    return {**agent_label(a), "ping": r}


# ---------------------------------------------------------------------------
# Inventar und Zustand
# ---------------------------------------------------------------------------


@tool()
async def trmm_get_agent_software(agent: str, search: str = "") -> dict[str, Any]:
    """Installierte Software eines Agents (Name, Version, Hersteller, Installationsdatum, Uninstall-Befehl).
    search: Teilstring im Namen oder Hersteller."""
    a = await resolve_agent(agent)
    data = await trmm().get(f"/software/{a['agent_id']}/") or {}
    sw = data.get("software") if isinstance(data, dict) else data
    sw = sw or []
    q = search.strip().lower()
    if q:
        sw = [s for s in sw if q in str(s.get("name", "")).lower() or q in str(s.get("publisher", "")).lower()]
    sw = sorted(sw, key=lambda s: str(s.get("name", "")).lower())
    return {**agent_label(a), "count": len(sw), "software": sw}


@tool()
async def trmm_get_agent_services(agent: str, search: str = "", status: str = "") -> dict[str, Any]:
    """Windows-Dienste eines Agents (live abgefragt). search: Teilstring in Name oder Anzeigename.
    status: z.B. running oder stopped."""
    a = await resolve_agent(agent)
    svcs = await trmm().get(f"/services/{a['agent_id']}/", timeout=40) or []
    q, st = search.strip().lower(), status.strip().lower()
    if q:
        svcs = [s for s in svcs if q in str(s.get("name", "")).lower() or q in str(s.get("display_name", "")).lower()]
    if st:
        svcs = [s for s in svcs if st == str(s.get("status", "")).lower()]
    keep = ("name", "display_name", "status", "start_type", "autodelay", "username", "pid", "binpath")
    rows = [{k: s.get(k) for k in keep if k in s} for s in svcs]
    return {**agent_label(a), "count": len(rows), "services": rows}


@tool()
async def trmm_get_agent_processes(agent: str, search: str = "", sort_by: str = "membytes", limit: int = 50) -> dict[str, Any]:
    """Laufende Prozesse eines Agents (live). sort_by: membytes oder cpu_percent. search: Teilstring im Namen."""
    a = await resolve_agent(agent)
    procs = await trmm().get(f"/agents/{a['agent_id']}/processes/", timeout=30) or []
    q = search.strip().lower()
    if q:
        procs = [p for p in procs if q in str(p.get("name", "")).lower()]
    key = sort_by if sort_by in ("membytes", "cpu_percent") else "membytes"

    def num(v: Any) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    procs = sorted(procs, key=lambda p: num(p.get(key)), reverse=True)
    items, truncated = _limit(procs, limit)
    return {**agent_label(a), "count": len(procs), "truncated": truncated, "processes": items}


@tool()
async def trmm_get_event_log(
    agent: str,
    log: str = "system",
    days: int = 1,
    level: str = "",
    search: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """Windows-Eventlog eines Agents (live). log: system, application oder security. days: 1-30.
    level: z.B. error, warning, information (Teilstring). search: Teilstring in Quelle oder Meldung.
    Neueste Einträge zuerst."""
    lg = guard.EVENT_LOGS.get(log.strip().lower())
    if not lg:
        raise GuardError("log muss system, application oder security sein.")
    d = int(days or 1)
    if not 1 <= d <= 30:
        raise GuardError("days muss zwischen 1 und 30 liegen.")
    a = await resolve_agent(agent)
    timeout = 200 if lg == "Security" else 60
    events = await trmm().get(f"/agents/{a['agent_id']}/eventlog/{lg}/{d}/", timeout=timeout) or []
    lv, q = level.strip().lower(), search.strip().lower()
    if lv:
        events = [e for e in events if lv in str(e.get("eventType", e.get("type", ""))).lower()]
    if q:
        events = [
            e for e in events
            if q in str(e.get("source", "")).lower() or q in str(e.get("message", "")).lower()
        ]
    events = sorted(events, key=lambda e: str(e.get("time", "")), reverse=True)
    items, truncated = _limit(events, limit)
    for e in items:
        if isinstance(e.get("message"), str):
            e["message"] = guard.truncate(e["message"], 2000)
    return {**agent_label(a), "log": lg, "days": d, "count": len(events), "truncated": truncated, "events": items}


@tool()
async def trmm_get_agent_checks(agent: str, only_failing: bool = False) -> dict[str, Any]:
    """Checks eines Agents mit Status, letzter Ausgabe und Zeitpunkt. only_failing: nur nicht bestandene.

    alert_severity ist der am Check eingestellte Schweregrad. current_severity ist der Schweregrad
    des letzten Laufs und wird nur bei nicht bestandenen Checks angezeigt. Bei Script-, CPU-,
    Memory- und Disk-Checks bestimmt Tactical ihn pro Lauf selbst (Script: Exit-Code in
    info/warning_return_codes = info/warning, sonst ungleich 0 = error)."""
    a = await resolve_agent(agent)
    checks = await trmm().get(f"/agents/{a['agent_id']}/checks/") or []
    rows = []
    for c in checks:
        res = c.get("check_result") or {}
        status = res.get("status", c.get("status"))
        row = {
            "id": c.get("id"),
            "name": c.get("readable_desc") or c.get("name"),
            "type": c.get("check_type"),
            "status": status,
            "alert_severity": c.get("alert_severity"),
            "last_run": res.get("last_run", c.get("last_run")),
            "more_info": guard.truncate(res.get("more_info", c.get("more_info")), 2000),
            "policy": bool(c.get("policy")),
        }
        if str(status).lower() == "failing" and res.get("alert_severity"):
            row["current_severity"] = res.get("alert_severity")
        if res.get("stdout") or res.get("stderr"):
            row["stdout"] = guard.truncate(res.get("stdout"), 2000)
            row["stderr"] = guard.truncate(res.get("stderr"), 2000)
            row["retcode"] = res.get("retcode")
        rows.append(row)
    if only_failing:
        rows = [r for r in rows if str(r.get("status")).lower() not in ("passing", "pending", "none")]
    return {**agent_label(a), "count": len(rows), "checks": rows}


@tool()
async def trmm_get_agent_tasks(agent: str) -> dict[str, Any]:
    """Automatisierte Tasks eines Agents (inkl. Policy-Tasks) mit letztem Lauf und Resultat."""
    a = await resolve_agent(agent)
    tasks = await trmm().get(f"/agents/{a['agent_id']}/tasks/") or []
    rows = []
    for t in tasks:
        res = t.get("task_result") or {}
        rows.append({
            "id": t.get("id"),
            "name": t.get("name"),
            "task_type": t.get("task_type"),
            "enabled": t.get("enabled"),
            "policy": bool(t.get("policy")),
            "schedule": t.get("schedule"),
            "status": res.get("status"),
            "sync_status": res.get("sync_status"),
            "last_run": res.get("last_run"),
            "retcode": res.get("retcode"),
            "stdout": guard.truncate(res.get("stdout"), 2000),
            "stderr": guard.truncate(res.get("stderr"), 2000),
        })
    return {**agent_label(a), "count": len(rows), "tasks": rows}


@tool()
async def trmm_get_windows_updates(agent: str, only_pending: bool = True) -> dict[str, Any]:
    """Windows-Updates eines Agents aus dem letzten Scan (KB, Titel, Schweregrad, Aktion, installiert).
    only_pending: nur nicht installierte."""
    a = await resolve_agent(agent)
    ups = await trmm().get(f"/winupdate/{a['agent_id']}/") or []
    keep = ("id", "kb", "title", "severity", "action", "installed", "downloaded", "date_installed", "result", "categories")
    rows = [{k: u.get(k) for k in keep if k in u} for u in ups]
    if only_pending:
        rows = [r for r in rows if not r.get("installed")]
    return {**agent_label(a), "count": len(rows), "updates": rows}


# ---------------------------------------------------------------------------
# Alerts, Verlauf, Notizen
# ---------------------------------------------------------------------------


@tool()
async def trmm_list_alerts(
    include_resolved: bool = False,
    include_snoozed: bool = False,
    days: int = 30,
    severity: list[str] | None = None,
    client_name: str = "",
    agent: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    """Alerts auflisten. Standard: offene, nicht geschlummerte Alerts der letzten 30 Tage.
    severity: Liste aus error, warning, info. client_name/agent: optionale Filter (Teilstring bzw. Agent)."""
    body: dict[str, Any] = {"timeFilter": max(1, min(int(days or 30), 3650))}
    if not include_resolved:
        body["resolvedFilter"] = False
    if not include_snoozed:
        body["snoozedFilter"] = False
    sev = [s.strip().lower() for s in (severity or []) if s.strip()]
    if sev:
        body["severityFilter"] = sev
    if client_name.strip():
        clients = await trmm().get("/clients/") or []
        ids = [c["id"] for c in clients if client_name.strip().lower() in str(c.get("name", "")).lower()]
        if not ids:
            raise GuardError(f"Kein Client passt zu '{client_name}'.")
        body["clientFilter"] = ids
    alerts = await trmm().patch("/alerts/", json=body, write=False) or []
    if agent.strip():
        a = await resolve_agent(agent)
        alerts = [x for x in alerts if x.get("agent_id") == a["agent_id"] or x.get("hostname") == a.get("hostname")]
    keep = (
        "id", "alert_time", "severity", "message", "hostname", "agent_id", "client", "site", "alert_type",
        "resolved", "resolved_on", "snoozed", "snooze_until",
    )
    rows = [{k: x.get(k) for k in keep if k in x} for x in alerts]
    rows.sort(key=lambda r: str(r.get("alert_time", "")), reverse=True)
    items, truncated = _limit(rows, limit)
    return {"count": len(rows), "truncated": truncated, "alerts": items}


@tool()
async def trmm_get_agent_history(agent: str, limit: int = 30) -> dict[str, Any]:
    """Verlauf eines Agents: zuletzt ausgeführte Befehle und Scripts (wer, wann, Resultat)."""
    a = await resolve_agent(agent)
    lim = max(1, min(int(limit or 30), 500))
    data = await trmm().get(f"/agents/v2/{a['agent_id']}/history/", params={"page": 1, "page_size": lim})
    rows = data.get("results", []) if isinstance(data, dict) else (data or [])
    out = []
    for h in rows[:lim]:
        res = h.get("script_results") or {}
        out.append({
            "id": h.get("id"),
            "time": h.get("time"),
            "type": h.get("type"),
            "username": h.get("username"),
            "command": h.get("command"),
            "script": h.get("script_name"),
            "results": guard.truncate(h.get("results"), 3000),
            "script_retcode": res.get("retcode") if isinstance(res, dict) else None,
            "script_stdout": guard.truncate(res.get("stdout"), 3000) if isinstance(res, dict) else None,
            "script_stderr": guard.truncate(res.get("stderr"), 3000) if isinstance(res, dict) else None,
        })
    return {**agent_label(a), "count": len(out), "history": out}


@tool()
async def trmm_get_agent_notes(agent: str) -> dict[str, Any]:
    """Notizen zu einem Agent."""
    a = await resolve_agent(agent)
    notes = await trmm().get(f"/agents/{a['agent_id']}/notes/") or []
    rows = [
        {"id": n.get("pk", n.get("id")), "entry_time": n.get("entry_time"), "username": n.get("username"), "note": n.get("note")}
        for n in notes
    ]
    return {**agent_label(a), "notes": rows}


@tool()
async def trmm_get_pending_actions(agent: str = "") -> dict[str, Any]:
    """Ausstehende Aktionen (z.B. geplante Reboots, Chocolatey-Installationen), optional für einen Agent."""
    if agent.strip():
        a = await resolve_agent(agent)
        rows = await trmm().get(f"/agents/{a['agent_id']}/pendingactions/") or []
        return {**agent_label(a), "pending_actions": rows}
    rows = await trmm().get("/logs/pendingactions/") or []
    return {"pending_actions": rows}


# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------


@tool()
async def trmm_list_scripts(search: str = "", category: str = "", shell: str = "", include_community: bool = True) -> dict[str, Any]:
    """Script-Bibliothek. search: Teilstring in Name oder Beschreibung. category/shell: Filter
    (shell z.B. powershell, cmd, python, shell)."""
    params = {"showCommunityScripts": "true" if include_community else "false"}
    scripts = await trmm().get("/scripts/", params=params) or []
    q, cat, sh = search.strip().lower(), category.strip().lower(), shell.strip().lower()
    rows = []
    for s in scripts:
        if q and q not in str(s.get("name", "")).lower() and q not in str(s.get("description", "")).lower():
            continue
        if cat and cat not in str(s.get("category", "")).lower():
            continue
        if sh and sh != str(s.get("shell", "")).lower():
            continue
        rows.append({k: s.get(k) for k in (
            "id", "name", "description", "category", "shell", "script_type", "args", "env_vars",
            "default_timeout", "run_as_user", "supported_platforms",
        ) if k in s})
    rows.sort(key=lambda r: (str(r.get("category")), str(r.get("name")).lower()))
    return {"count": len(rows), "scripts": rows}


@tool()
async def trmm_get_script(script_id: int) -> dict[str, Any]:
    """Ein Script aus der Bibliothek inklusive Code."""
    sid = guard.validate_positive_int(script_id, "script_id")
    s = await trmm().get(f"/scripts/{sid}/") or {}
    keep = (
        "id", "name", "description", "category", "shell", "script_type", "args", "env_vars", "default_timeout",
        "run_as_user", "supported_platforms", "script_body",
    )
    out = {k: s.get(k) for k in keep if k in s}
    if "script_body" in out:
        out["script_body"] = guard.truncate(out["script_body"])
    return out


@tool()
async def trmm_script_run_history(script_name: str = "", days: int = 7, limit: int = 50) -> dict[str, Any]:
    """Verlauf aller Script-Läufe (über alle Agents), optional für einen Script-Namen (exakt)."""
    end = dt.date.today()
    start = end - dt.timedelta(days=max(1, min(int(days or 7), 365)))
    params: dict[str, Any] = {"start": start.isoformat(), "end": end.isoformat(), "limit": max(1, min(int(limit or 50), 500))}
    if script_name.strip():
        params["scriptname"] = script_name.strip()
    rows = await trmm().get("/agents/scripthistory/", params=params) or []
    out = []
    for h in rows:
        res = h.get("script_results") or {}
        out.append({
            "id": h.get("id"),
            "time": h.get("time"),
            "username": h.get("username"),
            "script": h.get("script_name"),
            "agent_id": h.get("agent_id"),
            "retcode": res.get("retcode") if isinstance(res, dict) else None,
            "stdout": guard.truncate(res.get("stdout"), 1500) if isinstance(res, dict) else None,
            "stderr": guard.truncate(res.get("stderr"), 1500) if isinstance(res, dict) else None,
        })
    return {"count": len(out), "runs": out}
