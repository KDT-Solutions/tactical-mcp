"""MCPServer-Instanz, Tool-Registrierung mit Audit-Log, Client-Singleton und
Agent-Auflösung (Hostname oder Agent-ID)."""

from __future__ import annotations

import functools
import inspect
import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import audit, guard
from .config import settings
from .errors import GuardError, TrmmMcpError
from .trmm_client import TrmmClient
from .version import __version__

logger = logging.getLogger("tactical_mcp")

INSTRUCTIONS = (
    "tactical-mcp greift über die Tactical-RMM-API auf Clients, Sites und Agents zu: Inventar, Software, "
    "Dienste, Prozesse, Eventlogs, Checks, Tasks, Windows-Updates, Alerts und Verlauf auslesen sowie "
    "Befehle (cmd, PowerShell, bash), Ad-hoc-Scripts und gespeicherte Scripts auf Agents ausführen. "
    "Agents können per Hostname oder Agent-ID angegeben werden. Alles, was auf einem Agent etwas ausführt "
    "oder ändert, läuft nur mit confirm=true; ohne confirm kommt eine Vorschau. Für Diagnosen zuerst "
    "lesende Tools nutzen. Geschützte Agents und gesperrte Befehlsmuster werden blockiert."
)

mcp = MCPServer("tactical-mcp", version=__version__, instructions=INSTRUCTIONS)


def tool(*dargs: Any, **dkwargs: Any):
    """Wie mcp.tool(), zusätzlich:
    - jeder Aufruf wird als JSON-Zeile geloggt (Parameter ohne Secrets),
    - erwartete Fehler (TrmmMcpError) werden als ToolError mit Klartext gemeldet,
    - unerwartete Fehler nur mit Typ, ohne Details,
    - Resultate werden geschwärzt (bekannte Secret-Werte).
    Registriert wird der Wrapper; das Modul behält die Originalfunktion (Tests)."""
    register = mcp.tool(*dargs, **dkwargs)

    def decorator(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                params = dict(sig.bind_partial(*args, **kwargs).arguments)
            except TypeError:
                params = dict(kwargs)
            started = time.monotonic()
            fields: dict[str, Any] = {"tool": fn.__name__, "params": guard.redact_params(params)}
            try:
                result = fn(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
            except ToolError as exc:
                msg = guard.redact_text(str(exc))
                audit.log_event("tool_call", **fields, status="error", error=msg, duration_ms=_ms(started))
                raise ToolError(msg) from None
            except TrmmMcpError as exc:
                msg = guard.redact_text(str(exc))
                audit.log_event(
                    "tool_call", **fields, status="error", error_type=type(exc).__name__, error=msg,
                    duration_ms=_ms(started),
                )
                raise ToolError(msg) from None
            except Exception as exc:  # noqa: BLE001 - bewusst: keine Details nach aussen
                audit.log_event(
                    "tool_call", **fields, status="error", error_type=type(exc).__name__, duration_ms=_ms(started)
                )
                logger.exception("Unerwarteter Fehler in %s", fn.__name__)
                raise ToolError(f"Interner Fehler ({type(exc).__name__}). Details im Container-Log.") from None
            result = guard.redact(result)
            status = "preview" if isinstance(result, dict) and result.get("preview") is True else "ok"
            audit.log_event(
                "tool_call", **fields, status=status, result=audit.summarize_result(result), duration_ms=_ms(started)
            )
            return result

        register(wrapper)
        return fn

    return decorator


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_trmm: TrmmClient | None = None


def trmm() -> TrmmClient:
    global _trmm
    if _trmm is None:
        cfg = settings()
        missing = [n for n, v in (("TRMM_URL", cfg.trmm_url), ("TRMM_API_KEY", cfg.trmm_api_key)) if not v]
        if missing:
            raise TrmmMcpError(f"Konfiguration unvollständig, fehlende Umgebungsvariablen: {', '.join(missing)}")
        _trmm = TrmmClient(cfg.trmm_url, cfg.trmm_api_key, verify=cfg.trmm_tls_verify)
    return _trmm


def set_client(client: TrmmClient | None) -> None:
    """Nur für Tests: Client ersetzen bzw. zurücksetzen."""
    global _trmm
    _trmm = client


# ---------------------------------------------------------------------------
# Agent-Auflösung
# ---------------------------------------------------------------------------


async def list_agents_brief() -> list[dict[str, Any]]:
    data = await trmm().get("/agents/", params={"detail": "true"})
    return data if isinstance(data, list) else []


async def resolve_agent(agent: str) -> dict[str, Any]:
    """Findet einen Agent über Agent-ID oder Hostname (Gross-/Kleinschreibung egal).
    Liefert die Zeile aus der Agent-Liste (hostname, agent_id, client_name, site_name, status, ...)."""
    ref = (agent or "").strip()
    if not ref:
        raise GuardError("agent fehlt (Hostname oder Agent-ID).")
    agents = await list_agents_brief()
    exact_id = [a for a in agents if a.get("agent_id") == ref]
    if exact_id:
        return exact_id[0]
    low = ref.lower()
    by_host = [a for a in agents if str(a.get("hostname", "")).lower() == low]
    if len(by_host) == 1:
        return by_host[0]
    if len(by_host) > 1:
        raise GuardError(
            f"Hostname '{ref}' ist mehrdeutig. Bitte Agent-ID angeben: "
            + "; ".join(f"{a.get('agent_id')} ({a.get('client_name')}/{a.get('site_name')})" for a in by_host)
        )
    partial = [a for a in agents if low in str(a.get("hostname", "")).lower()]
    if len(partial) == 1:
        return partial[0]
    if partial:
        names = ", ".join(sorted(str(a.get("hostname")) for a in partial)[:20])
        raise GuardError(f"Kein eindeutiger Agent für '{ref}'. Treffer: {names}")
    raise GuardError(f"Kein Agent mit Hostname oder Agent-ID '{ref}' gefunden.")


def agent_label(a: dict[str, Any]) -> dict[str, Any]:
    """Kurzbeschreibung eines Agents für Vorschauen und Resultate."""
    return {
        "hostname": a.get("hostname"),
        "agent_id": a.get("agent_id"),
        "client": a.get("client_name"),
        "site": a.get("site_name"),
        "status": a.get("status"),
        "plat": a.get("plat"),
        "logged_in_user": a.get("logged_username") or a.get("last_logged_in_user"),
    }
