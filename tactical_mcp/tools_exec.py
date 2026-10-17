"""Ausführende und ändernde Tools: Befehle (cmd, PowerShell, bash), Ad-hoc-Scripts,
gespeicherte Scripts, Dienste, Prozesse, Reboot, Updates, Checks, Tasks,
Wartungsmodus, Notizen, Alerts.

Für alle gilt: TRMM_READ_ONLY sperrt sie, geschützte Agents werden blockiert,
ohne confirm=true kommt nur eine Vorschau. Gelöscht wird nichts (keine Agents,
Clients, Sites oder Scripts).
"""

from __future__ import annotations

from typing import Any

from . import guard
from .app import agent_label, resolve_agent, tool, trmm
from .errors import GuardError

WINDOWS_ONLY = "nur für Windows-Agents verfügbar"


async def _target(agent: str, need_online: bool = True) -> dict[str, Any]:
    """Prüfungen, die vor jeder Aktion auf einem Agent laufen."""
    guard.require_writable()
    a = await resolve_agent(agent)
    guard.check_agent_allowed(a)
    if need_online and str(a.get("status", "")).lower() != "online":
        raise GuardError(
            f"Agent {a.get('hostname')} ist nicht online (Status: {a.get('status')}). "
            "Mit trmm_ping_agent prüfen oder warten, bis er wieder verbunden ist."
        )
    return a


def _is_windows(a: dict[str, Any]) -> bool:
    return str(a.get("plat", "windows")).lower() == "windows"


def _shell_for_agent(a: dict[str, Any], shell: str) -> str:
    s = guard.validate_command_shell(shell)
    if _is_windows(a) and s == "bash":
        raise GuardError("bash gibt es nur auf Linux-/macOS-Agents. Für Windows cmd oder powershell nutzen.")
    if not _is_windows(a) and s in ("cmd", "powershell"):
        raise GuardError(f"{s} gibt es nur auf Windows-Agents. Für Linux/macOS bash nutzen.")
    return "/bin/bash" if s == "bash" else s


def _result(a: dict[str, Any], action: str, response: Any, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"executed": True, "action": action, **agent_label(a), **extra}
    if isinstance(response, dict):
        out["result"] = {k: guard.truncate(v) for k, v in response.items()}
    else:
        out["result"] = guard.truncate(response)
    return out


# ---------------------------------------------------------------------------
# Befehle und Scripts
# ---------------------------------------------------------------------------


@tool()
async def trmm_run_command(
    agent: str,
    command: str,
    shell: str = "powershell",
    timeout: int = 60,
    run_as_user: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Führt einen einzelnen Befehl auf einem Agent aus und liefert die Ausgabe.

    shell: powershell oder cmd (Windows), bash (Linux/macOS). timeout: Sekunden.
    run_as_user: im Kontext des angemeldeten Benutzers statt als SYSTEM/root.
    Für mehrzeilige Logik trmm_run_script_code verwenden. Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    sh = _shell_for_agent(a, shell)
    cmd = (command or "").strip()
    if not cmd:
        raise GuardError("command ist leer.")
    guard.check_command_allowed(cmd)
    t = guard.validate_timeout(timeout, 60)
    details = {"agent": agent_label(a), "shell": sh, "command": cmd, "timeout": t, "run_as_user": bool(run_as_user)}
    if not confirm:
        return guard.preview("run_command", **details)
    payload = {"shell": sh, "cmd": cmd, "timeout": t, "custom_shell": None, "run_as_user": bool(run_as_user)}
    r = await trmm().post(f"/agents/{a['agent_id']}/cmd/", json=payload, timeout=t + 15)
    return _result(a, "run_command", r, shell=sh, command=cmd)


@tool()
async def trmm_run_script_code(
    agent: str,
    code: str,
    language: str = "powershell",
    args: list[str] | None = None,
    env_vars: list[str] | None = None,
    timeout: int = 120,
    run_as_user: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Führt Ad-hoc-Code als Script auf einem Agent aus (ohne ihn in der Bibliothek zu speichern)
    und liefert stdout, stderr, Exit-Code und Laufzeit.

    language: powershell, cmd, python, shell, nushell oder deno. args: Script-Argumente.
    env_vars: Liste "NAME=wert". Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    lang = guard.validate_script_shell(language)
    if _is_windows(a) and lang == "shell":
        raise GuardError("language 'shell' ist für Linux/macOS. Für Windows powershell oder cmd nutzen.")
    if not _is_windows(a) and lang in ("powershell", "cmd"):
        raise GuardError(f"{lang} gibt es nur auf Windows-Agents.")
    body = code or ""
    if not body.strip():
        raise GuardError("code ist leer.")
    arg_list = guard.validate_str_list(args, "args")
    env_list = guard.validate_str_list(env_vars, "env_vars")
    guard.check_command_allowed(body, " ".join(arg_list))
    t = guard.validate_timeout(timeout, 120)
    details = {
        "agent": agent_label(a), "language": lang, "code": guard.truncate(body, 8000), "args": arg_list,
        "env_var_names": [e.split("=", 1)[0] for e in env_list], "timeout": t, "run_as_user": bool(run_as_user),
    }
    if not confirm:
        return guard.preview("run_script_code", **details)
    payload = {
        "code": body, "shell": lang, "args": arg_list, "env_vars": env_list, "timeout": t,
        "run_as_user": bool(run_as_user),
    }
    r = await trmm().post(f"/scripts/{a['agent_id']}/test/", json=payload, timeout=t + 15)
    return _result(a, "run_script_code", r, language=lang)


@tool()
async def trmm_run_script(
    agent: str,
    script_id: int = 0,
    script_name: str = "",
    args: list[str] | None = None,
    env_vars: list[str] | None = None,
    timeout: int = 0,
    run_as_user: bool = False,
    wait: bool = True,
    confirm: bool = False,
) -> dict[str, Any]:
    """Führt ein gespeichertes Script aus der Tactical-Bibliothek auf einem Agent aus.

    script_id oder script_name (exakter Name). timeout: 0 = Standard-Timeout des Scripts.
    wait: true = auf Ergebnis warten und Ausgabe liefern, false = nur starten.
    Ohne confirm=true nur Vorschau (mit Script-Code)."""
    a = await _target(agent)
    if script_id:
        sid = guard.validate_positive_int(script_id, "script_id")
    elif script_name.strip():
        scripts = await trmm().get("/scripts/", params={"showCommunityScripts": "true"}) or []
        hits = [s for s in scripts if str(s.get("name", "")).strip().lower() == script_name.strip().lower()]
        if len(hits) != 1:
            raise GuardError(
                f"Script '{script_name}' nicht eindeutig gefunden ({len(hits)} Treffer). "
                "trmm_list_scripts nutzen und script_id angeben."
            )
        sid = int(hits[0]["id"])
    else:
        raise GuardError("script_id oder script_name angeben.")
    s = await trmm().get(f"/scripts/{sid}/") or {}
    arg_list = guard.validate_str_list(args, "args") if args is not None else list(s.get("args") or [])
    env_list = guard.validate_str_list(env_vars, "env_vars") if env_vars is not None else list(s.get("env_vars") or [])
    guard.check_command_allowed(str(s.get("script_body", "")), " ".join(arg_list))
    t = guard.validate_timeout(timeout or s.get("default_timeout") or 120, 120)
    details = {
        "agent": agent_label(a), "script_id": sid, "script_name": s.get("name"), "language": s.get("shell"),
        "args": arg_list, "env_var_names": [e.split("=", 1)[0] for e in env_list], "timeout": t,
        "run_as_user": bool(run_as_user or s.get("run_as_user")), "wait": bool(wait),
        "code": guard.truncate(s.get("script_body"), 8000),
    }
    if not confirm:
        return guard.preview("run_script", **details)
    payload = {
        "script": sid, "output": "wait" if wait else "forget", "args": arg_list, "env_vars": env_list,
        "timeout": t, "run_as_user": bool(run_as_user), "run_on_server": False,
    }
    r = await trmm().post(f"/agents/{a['agent_id']}/runscript/", json=payload, timeout=(t + 20) if wait else 30)
    return _result(a, "run_script", r, script_id=sid, script_name=s.get("name"))


# ---------------------------------------------------------------------------
# Dienste, Prozesse, Neustart
# ---------------------------------------------------------------------------


@tool()
async def trmm_service_action(agent: str, service: str, action: str, confirm: bool = False) -> dict[str, Any]:
    """Windows-Dienst starten, stoppen oder neu starten. service: Dienstname (nicht Anzeigename).
    action: start, stop oder restart. Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    if not _is_windows(a):
        raise GuardError(f"Dienstaktionen sind {WINDOWS_ONLY}. Für Linux trmm_run_command mit systemctl nutzen.")
    name = guard.validate_service_name(service)
    act = (action or "").strip().lower()
    if act not in guard.SERVICE_ACTIONS:
        raise GuardError("action muss start, stop oder restart sein.")
    if act in ("stop", "restart") and any(x in name.lower() for x in ("tacticalrmm", "tacticalagent", "mesh agent", "meshagent")):
        raise GuardError("Der Tactical-/Mesh-Agent-Dienst wird hier nicht gestoppt (sonst ist der Agent weg). trmm_recover_agent nutzen.")
    if not confirm:
        try:
            detail = await trmm().get(f"/services/{a['agent_id']}/{name}/", timeout=40)
        except Exception:  # noqa: BLE001 - Vorschau soll auch ohne Details gehen
            detail = None
        return guard.preview("service_action", agent=agent_label(a), service=name, service_action=act, current=detail)
    r = await trmm().post(f"/services/{a['agent_id']}/{name}/", json={"sv_action": act}, timeout=80)
    return _result(a, "service_action", r, service=name, service_action=act)


@tool()
async def trmm_kill_process(agent: str, pid: int, confirm: bool = False) -> dict[str, Any]:
    """Beendet einen Prozess über seine PID (siehe trmm_get_agent_processes). Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    p = guard.validate_positive_int(pid, "pid")
    procs = await trmm().get(f"/agents/{a['agent_id']}/processes/", timeout=30) or []
    match = next((x for x in procs if int(x.get("pid", -1)) == p), None)
    if not match:
        raise GuardError(f"Kein Prozess mit PID {p} auf {a.get('hostname')} gefunden.")
    pname = str(match.get("name", "")).lower()
    if any(x in pname for x in ("tacticalrmm", "tacticalagent", "meshagent")):
        raise GuardError("Der Tactical-/Mesh-Agent-Prozess wird hier nicht beendet.")
    if not confirm:
        return guard.preview("kill_process", agent=agent_label(a), pid=p, process=match)
    r = await trmm().delete(f"/agents/{a['agent_id']}/processes/{p}/", timeout=30)
    return _result(a, "kill_process", r, pid=p, process_name=match.get("name"))


@tool()
async def trmm_reboot_agent(agent: str, confirm: bool = False) -> dict[str, Any]:
    """Startet den Agent sofort neu. Ohne confirm=true nur Vorschau (inkl. angemeldetem Benutzer)."""
    a = await _target(agent)
    if not confirm:
        return guard.preview("reboot", agent=agent_label(a), warnung="Sofortiger Neustart, angemeldete Benutzer verlieren ungesicherte Arbeit.")
    r = await trmm().post(f"/agents/{a['agent_id']}/reboot/", json={}, timeout=30)
    return _result(a, "reboot", r)


@tool()
async def trmm_shutdown_agent(agent: str, confirm: bool = False) -> dict[str, Any]:
    """Fährt den Agent herunter. Danach ist er nur noch vor Ort oder per Wake-on-LAN erreichbar.
    Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    if not confirm:
        return guard.preview("shutdown", agent=agent_label(a), warnung="Gerät ist danach aus und über Tactical nicht mehr erreichbar.")
    r = await trmm().post(f"/agents/{a['agent_id']}/shutdown/", json={}, timeout=30)
    return _result(a, "shutdown", r)


@tool()
async def trmm_recover_agent(agent: str, mode: str = "mesh", confirm: bool = False) -> dict[str, Any]:
    """Verbindung reparieren. mode: mesh (MeshCentral-Agent neu verbinden) oder tacagent
    (Tactical-Agent-Dienst neu starten). Ohne confirm=true nur Vorschau."""
    a = await _target(agent, need_online=False)
    m = (mode or "").strip().lower()
    if m not in ("mesh", "tacagent"):
        raise GuardError("mode muss mesh oder tacagent sein.")
    if not confirm:
        return guard.preview("recover", agent=agent_label(a), mode=m)
    r = await trmm().post(f"/agents/{a['agent_id']}/recover/", json={"mode": m}, timeout=60)
    return _result(a, "recover", r, mode=m)


# ---------------------------------------------------------------------------
# Updates, Checks, Tasks
# ---------------------------------------------------------------------------


@tool()
async def trmm_scan_windows_updates(agent: str, confirm: bool = False) -> dict[str, Any]:
    """Startet einen Windows-Update-Scan auf dem Agent (Ergebnis danach mit trmm_get_windows_updates).
    Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    if not _is_windows(a):
        raise GuardError(f"Windows-Updates sind {WINDOWS_ONLY}.")
    if not confirm:
        return guard.preview("scan_windows_updates", agent=agent_label(a))
    r = await trmm().post(f"/winupdate/{a['agent_id']}/scan/", json={}, timeout=30)
    return _result(a, "scan_windows_updates", r)


@tool()
async def trmm_install_windows_updates(agent: str, confirm: bool = False) -> dict[str, Any]:
    """Installiert die gemäss Patch-Policy genehmigten Windows-Updates. Je nach Policy startet der
    Agent danach neu. Ohne confirm=true nur Vorschau mit den offenen Updates."""
    a = await _target(agent)
    if not _is_windows(a):
        raise GuardError(f"Windows-Updates sind {WINDOWS_ONLY}.")
    if not confirm:
        ups = await trmm().get(f"/winupdate/{a['agent_id']}/") or []
        pending = [
            {k: u.get(k) for k in ("kb", "title", "severity", "action")} for u in ups if not u.get("installed")
        ]
        return guard.preview(
            "install_windows_updates", agent=agent_label(a), pending_updates=pending,
            hinweis_policy="Installiert werden die von der Patch-Policy genehmigten Updates; ein Neustart ist je nach Policy möglich.",
        )
    r = await trmm().post(f"/winupdate/{a['agent_id']}/install/", json={}, timeout=30)
    return _result(a, "install_windows_updates", r)


@tool()
async def trmm_run_checks(agent: str, confirm: bool = False) -> dict[str, Any]:
    """Führt alle Checks des Agents sofort aus. Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    if not confirm:
        return guard.preview("run_checks", agent=agent_label(a))
    r = await trmm().post(f"/checks/{a['agent_id']}/run/", json={}, timeout=60)
    return _result(a, "run_checks", r)


@tool()
async def trmm_run_task(agent: str, task_id: int, confirm: bool = False) -> dict[str, Any]:
    """Führt einen automatisierten Task (siehe trmm_get_agent_tasks) sofort auf dem Agent aus.
    Ohne confirm=true nur Vorschau."""
    a = await _target(agent)
    tid = guard.validate_positive_int(task_id, "task_id")
    tasks = await trmm().get(f"/agents/{a['agent_id']}/tasks/") or []
    task = next((t for t in tasks if int(t.get("id", -1)) == tid), None)
    if not task:
        raise GuardError(f"Task {tid} gehört nicht zu {a.get('hostname')}.")
    if not confirm:
        return guard.preview("run_task", agent=agent_label(a), task={"id": tid, "name": task.get("name"), "policy": bool(task.get("policy"))})
    body = {"agent_id": a["agent_id"]} if task.get("policy") else {}
    r = await trmm().post(f"/tasks/{tid}/run/", json=body, timeout=30)
    return _result(a, "run_task", r, task_id=tid, task_name=task.get("name"))


# ---------------------------------------------------------------------------
# Wartungsmodus, Notizen, Alerts
# ---------------------------------------------------------------------------


@tool()
async def trmm_set_maintenance_mode(agent: str, enabled: bool, confirm: bool = False) -> dict[str, Any]:
    """Wartungsmodus eines Agents ein- oder ausschalten (unterdrückt Alerts). Ohne confirm=true nur Vorschau."""
    a = await _target(agent, need_online=False)
    if not confirm:
        return guard.preview("set_maintenance_mode", agent=agent_label(a), current=a.get("maintenance_mode"), new=bool(enabled))
    r = await trmm().put(f"/agents/{a['agent_id']}/", json={"maintenance_mode": bool(enabled)})
    return _result(a, "set_maintenance_mode", r, maintenance_mode=bool(enabled))


@tool()
async def trmm_add_agent_note(agent: str, note: str, confirm: bool = False) -> dict[str, Any]:
    """Notiz an einen Agent anhängen (z.B. was gefixt wurde). Ohne confirm=true nur Vorschau."""
    guard.require_writable()
    a = await resolve_agent(agent)
    text = (note or "").strip()
    if not text:
        raise GuardError("note ist leer.")
    if not confirm:
        return guard.preview("add_agent_note", agent=agent_label(a), note=text)
    r = await trmm().post("/agents/notes/", json={"agent_id": a["agent_id"], "note": text})
    return _result(a, "add_agent_note", r)


@tool()
async def trmm_alert_action(alert_id: int, action: str, snooze_days: int = 1, confirm: bool = False) -> dict[str, Any]:
    """Alert auflösen oder schlummern. action: resolve, snooze oder unsnooze. snooze_days nur bei snooze.
    Ohne confirm=true nur Vorschau."""
    guard.require_writable()
    aid = guard.validate_positive_int(alert_id, "alert_id")
    act = (action or "").strip().lower()
    if act not in ("resolve", "snooze", "unsnooze"):
        raise GuardError("action muss resolve, snooze oder unsnooze sein.")
    alert = await trmm().get(f"/alerts/{aid}/") or {}
    host = alert.get("hostname", "")
    if guard.agent_protection(host, alert.get("agent_id", "")):
        raise GuardError(guard.agent_protection(host, alert.get("agent_id", "")) or "")
    body: dict[str, Any] = {"type": act}
    if act == "snooze":
        d = int(snooze_days or 1)
        if not 1 <= d <= 365:
            raise GuardError("snooze_days muss zwischen 1 und 365 liegen.")
        body["snooze_days"] = d
    summary = {k: alert.get(k) for k in ("id", "hostname", "severity", "message", "alert_time", "resolved", "snoozed")}
    if not confirm:
        return guard.preview("alert_action", alert=summary, alert_action=act, **({"snooze_days": body["snooze_days"]} if act == "snooze" else {}))
    await trmm().put(f"/alerts/{aid}/", json=body)
    return {"executed": True, "action": "alert_action", "alert_id": aid, "alert_action": act, "alert": summary}
