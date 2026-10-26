"""Schutzregeln, confirm-Logik, Eingabeprüfung und Schwärzung.

- confirm: Jedes Tool, das auf einem Agent etwas ausführt oder ändert, läuft nur
  mit confirm=true. Ohne confirm kommt eine Vorschau (Agent, Client, Site,
  Online-Status, Shell, Befehl).
- TRMM_READ_ONLY=1 sperrt alle ausführenden/ändernden Tools.
- MCP_ALLOW_EXEC (Default aus): Befehle, Ad-hoc-Code, Bibliotheks-Scripts sowie
  das Anlegen von Scripts, Script-Checks und Script-Tasks gehen nur, wenn der
  Schalter serverseitig gesetzt ist. Das ist die eigentliche Sicherheitsgrenze
  gegen Code-Ausführung - nicht die Befehlsliste.
- PROTECTED_AGENTS: Hostnamen bzw. Agent-IDs (fnmatch-Muster), auf denen nichts
  ausgeführt oder geändert wird - auch nicht indirekt über Policies.
- Gesperrte Befehlsmuster (feste Liste + BLOCKED_COMMAND_PATTERNS), geprüft auf
  dem Rohtext und auf normalisierten Varianten (Kleinschreibung, Leerraum,
  ^-/`-Escapes, String-Verkettung), damit die gängigen Umgehungen nicht greifen.
- Schwärzung: bekannte Secret-Werte aus der Konfiguration erscheinen nie in
  Ausgaben oder Logs; Parameter mit Secret-Namen werden im Log maskiert,
  env_vars nur mit Namen geloggt, Befehls-/Code-Parameter gekürzt.
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


def validate_timeout(value: Any, default: int = 60, maximum: int | None = None) -> int:
    try:
        t = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        raise GuardError("timeout muss eine Zahl (Sekunden) sein.") from None
    mx = maximum or settings().max_timeout
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


def require_exec() -> None:
    """Befehls-/Script-Ausführung und das Anlegen von Scripts, Script-Checks und
    Script-Tasks sind nur mit MCP_ALLOW_EXEC=1 freigeschaltet (Default aus)."""
    require_writable()
    if not settings().allow_exec:
        raise GuardError(
            "Befehls- und Script-Ausführung ist auf diesem Server deaktiviert (MCP_ALLOW_EXEC nicht gesetzt). "
            "Lesende Tools, Dienste, Prozesse, Neustart, Updates, Checks/Tasks ausführen, Wartungsmodus, "
            "Notizen und Alerts gehen weiterhin. Freischalten nur serverseitig über die Stack-Variable "
            "MCP_ALLOW_EXEC=1."
        )


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


_WS_RE = re.compile(r"\s+")


def normalized_variants(text: str) -> tuple[str, ...]:
    """Rohtext plus normalisierte Fassungen, gegen die die Sperrliste geprüft wird.

    1. Rohtext (wie bisher, mit MULTILINE).
    2. Kleinschreibung, Zeilenumbrüche und Mehrfach-Leerzeichen zu einem Leerzeichen,
       cmd-Escapes (^) und PowerShell-Escapes (`) entfernt - fängt dis^kpart, dis`kpart.
    3. Zusätzlich Anführungszeichen und '+' entfernt - fängt String-Verkettung
       wie 'diskp'+'art' oder "format" + " c:".
    Falsch-Positive sind dabei bewusst in Kauf genommen (lieber einmal zu viel blockieren)."""
    raw = text or ""
    collapsed = _WS_RE.sub(" ", raw.lower().replace("^", "").replace("`", "")).strip()
    joined = _WS_RE.sub(" ", collapsed.replace("'", "").replace('"', "").replace("+", "")).strip()
    return (raw, collapsed, joined)


def blocked_reason(text: str) -> str | None:
    """Prüft Befehls- bzw. Script-Text (roh und normalisiert) gegen die gesperrten Muster."""
    variants = normalized_variants(text)
    for p in settings().blocked_command_patterns:
        try:
            rx = re.compile(p, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        if any(rx.search(v) for v in variants):
            return f"Befehl blockiert (gesperrtes Muster: {p}). Solche Aktionen nur direkt in Tactical ausführen."
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


# Parameter, die Befehle, Code oder Argumente tragen: im Audit-Log nur gekürzt und
# mit maskierten Inline-Secrets (z.B. "net user x P@ss", "-p geheim", "PASSWORD=...").
LOG_TRUNCATE_PARAMS = {"command", "code", "args", "note"}
LOG_PARAM_MAX_CHARS = 200
_INLINE_SECRET_RE = re.compile(
    r"((?:[\w-]*(?:password|passwd|pwd|token|api_?key|secret|credential)[\w-]*)\s*[=:]\s*)(\S+)", re.IGNORECASE
)
_FLAG_SECRET_RE = re.compile(r"((?:^|\s)(?:-p|/p|--password|-password|-pass|/pass|-pw|/pw)[\s:=]+)(\S+)", re.IGNORECASE)


def mask_inline_secrets(text: str) -> str:
    out = _INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{MASK}", text or "")
    return _FLAG_SECRET_RE.sub(lambda m: f"{m.group(1)}{MASK}", out)


_SECRET_FLAG_RE = re.compile(r"^(-p|/p|--password|-password|-pass|/pass|-pw|/pw)$", re.IGNORECASE)


def _log_value(value: Any) -> Any:
    """Kürzt Befehls-/Code-Parameter fürs Log und maskiert Secrets darin
    (bei Argumentlisten auch den Wert nach einem Passwort-Flag)."""
    if isinstance(value, str):
        return truncate(mask_inline_secrets(redact_text(value)), LOG_PARAM_MAX_CHARS)
    if isinstance(value, list):
        out = []
        prev_flag = False
        for v in value:
            out.append(MASK if (prev_flag and isinstance(v, str)) else _log_value(v))
            prev_flag = isinstance(v, str) and bool(_SECRET_FLAG_RE.match(v.strip()))
        return out
    return redact(value)


def env_var_names(values: Any) -> Any:
    """Aus einer Liste "NAME=wert" nur die Namen (wie in der Vorschau)."""
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return values
    return [str(v).split("=", 1)[0] for v in values]


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in params.items():
        if SECRET_NAME_RE.search(k):
            out[k] = MASK
        elif k == "env_vars":
            out[k] = env_var_names(v)
        elif k in LOG_TRUNCATE_PARAMS:
            out[k] = _log_value(v)
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
