"""Schutzregeln, confirm-Logik, Eingabeprüfung und Schwärzung.

- confirm: Jedes Tool, das auf einem Agent etwas ausführt oder ändert, läuft nur
  mit confirm=true. Ohne confirm kommt eine Vorschau (Agent, Client, Site,
  Online-Status, Shell, Befehl).
- TRMM_READ_ONLY=1 sperrt alle ausführenden/ändernden Tools.
- PROTECTED_AGENTS: Hostnamen bzw. Agent-IDs (fnmatch-Muster), auf denen nichts
  ausgeführt oder geändert wird.
- Gesperrte Befehlsmuster (feste Liste + BLOCKED_COMMAND_PATTERNS).
- Schwärzung: bekannte Secret-Werte aus der Konfiguration erscheinen nie in
  Ausgaben oder Logs; Parameter mit Secret-Namen werden im Log maskiert.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Iterable

from .config import settings
from .errors import GuardError

MASK = "***"

SECRET_NAME_RE = re.compile(r"(PASSWORD|PASSWD|TOKEN|API_?KEY|SECRET|CREDENTIAL)", re.IGNORECASE)

COMMAND_SHELLS = {"cmd", "powershell", "bash"}
SCRIPT_SHELLS = {"powershell", "cmd", "python", "shell", "nushell", "deno"}
SERVICE_ACTIONS = {"start", "stop", "restart"}
EVENT_LOGS = {"application": "Application", "system": "System", "security": "Security"}

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{20,64}$")
_SVC_RE = re.compile(r"^[A-Za-z0-9_.@$ -]{1,256}$")


# ---------------------------------------------------------------------------
# Eingabeprüfung
# ---------------------------------------------------------------------------


def looks_like_agent_id(value: str) -> bool:
    return bool(_AGENT_ID_RE.match((value or "").strip()))


def validate_timeout(value: Any, default: int = 60) -> int:
    try:
        t = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        raise GuardError("timeout muss eine Zahl (Sekunden) sein.") from None
    mx = settings().max_timeout
    if t < 5 or t > mx:
        raise GuardError(f"timeout muss zwischen 5 und {mx} Sekunden liegen.")
    return t


def validate_command_shell(shell: str) -> str:
    s = (shell or "").strip().lower()
    if s not in COMMAND_SHELLS:
        raise GuardError(f"Ungültige Shell {shell!r}. Erlaubt: {', '.join(sorted(COMMAND_SHELLS))}.")
    return s


def validate_script_shell(shell: str) -> str:
    s = (shell or "").strip().lower()
    if s not in SCRIPT_SHELLS:
        raise GuardError(f"Ungültige Script-Sprache {shell!r}. Erlaubt: {', '.join(sorted(SCRIPT_SHELLS))}.")
    return s


def validate_service_name(name: str) -> str:
    n = (name or "").strip()
    if not _SVC_RE.match(n):
        raise GuardError(f"Ungültiger Dienstname: {name!r}")
    return n


def validate_positive_int(value: Any, label: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise GuardError(f"{label} muss eine positive Ganzzahl sein.") from None
    if v < 1:
        raise GuardError(f"{label} muss eine positive Ganzzahl sein.")
    return v


def validate_str_list(values: Iterable[str] | str | None, label: str) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values] if values.strip() else []
    out = []
    for v in values:
        if not isinstance(v, str):
            raise GuardError(f"{label} muss eine Liste von Texten sein.")
        out.append(v)
    return out


# ---------------------------------------------------------------------------
# Schutzregeln
# ---------------------------------------------------------------------------


def require_writable() -> None:
    if settings().read_only:
        raise GuardError("tactical-mcp läuft im Nur-Lese-Modus (TRMM_READ_ONLY=1). Ausführen und Ändern ist gesperrt.")


def agent_protection(hostname: str, agent_id: str) -> str | None:
    pats = settings().protected_agents
    for value in (hostname or "", agent_id or ""):
        v = value.strip().lower()
        for p in pats:
            if v and fnmatch.fnmatchcase(v, p):
                return f"Agent '{hostname or agent_id}' ist geschützt (Muster '{p}' in PROTECTED_AGENTS)."
    return None


def check_agent_allowed(agent: dict[str, Any]) -> None:
    reason = agent_protection(agent.get("hostname", ""), agent.get("agent_id", ""))
    if reason:
        raise GuardError(reason)


def blocked_reason(text: str) -> str | None:
    """Prüft Befehls- bzw. Script-Text gegen die gesperrten Muster."""
    t = text or ""
    for p in settings().blocked_command_patterns:
        try:
            if re.search(p, t, re.IGNORECASE | re.MULTILINE):
                return f"Befehl blockiert (gesperrtes Muster: {p}). Solche Aktionen nur direkt in Tactical ausführen."
        except re.error:
            continue
    return None


def check_command_allowed(*texts: str) -> None:
    for t in texts:
        reason = blocked_reason(t)
        if reason:
            raise GuardError(reason)


# ---------------------------------------------------------------------------
# confirm
# ---------------------------------------------------------------------------


def preview(action: str, **details: Any) -> dict[str, Any]:
    return {
        "preview": True,
        "executed": False,
        "action": action,
        **details,
        "hinweis": "Nichts ausgeführt. Zum Ausführen denselben Aufruf mit confirm=true wiederholen.",
    }


# ---------------------------------------------------------------------------
# Schwärzung und Kürzung
# ---------------------------------------------------------------------------


def redact_text(text: str) -> str:
    out = text or ""
    for s in settings().secret_values():
        out = out.replace(s, MASK)
    return out


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in params.items():
        if SECRET_NAME_RE.search(k):
            out[k] = MASK
        else:
            out[k] = redact(v)
    return out


def truncate(text: Any, limit: int | None = None) -> Any:
    """Kürzt lange Ausgaben (Anfang und Ende bleiben erhalten)."""
    if not isinstance(text, str):
        return text
    lim = limit or settings().max_output_chars
    if len(text) <= lim:
        return text
    head = int(lim * 0.6)
    tail = lim - head
    cut = len(text) - lim
    return f"{text[:head]}\n\n[... {cut} Zeichen gekürzt ...]\n\n{text[-tail:]}"
