"""Konfiguration ausschliesslich über Umgebungsvariablen (siehe README).

Secrets (TRMM_API_KEY, MCP_API_KEY) kommen nur aus der Umgebung bzw. den
Portainer-Stack-Variablen und werden nie ins Image gebaut.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Grobe Notbremse gegen offensichtlich zerstörerische Befehle. Sie ersetzt nicht
# die confirm-Pflicht, verhindert aber, dass ein Tippfehler oder eine falsch
# verstandene Anweisung eine Platte löscht. Gilt immer, zusätzlich zu
# BLOCKED_COMMAND_PATTERNS - per Env lässt sie sich nicht abschalten.
DEFAULT_BLOCKED_COMMAND_PATTERNS = (
    r"\bformat(\.com)?\s+[a-z]:",                      # format C:
    r"\bformat-volume\b",
    r"\bclear-disk\b",
    r"\binitialize-disk\b",
    r"\bdiskpart\b",
    r"\bcipher(\.exe)?\s+/w",
    r"\bvssadmin(\.exe)?\s+delete\s+shadows",
    r"\bwmic(\.exe)?\s+shadowcopy\s+delete",
    r"\bwbadmin(\.exe)?\s+delete\b",
    r"\bbcdedit(\.exe)?\s+/(delete|deletevalue)\b",
    r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)[a-z]*\s+/(\s|$|\*)",  # rm -rf /
    r"\bmkfs(\.[a-z0-9]+)?\b",
    r"\bdd\s+[^|]*\bof=/dev/(sd|nvme|hd|vd|xvd)",
    r"\bremove-item\b[^|;]*-recurse[^|;]*\s[\"']?[a-z]:\\?[\"']?(\s|$)",  # Remove-Item -Recurse C:\
    r"\b(rd|rmdir)\s+/s\s+(/q\s+)?[\"']?[a-z]:\\?[\"']?(\s|$)",          # rd /s C:\
    r"\bdel\s+(/[a-z]\s+)*[\"']?[a-z]:\\\*",                              # del C:\*
    r"tacticalagent.*unins|unins.*tacticalagent",                          # Agent nicht deinstallieren
    r"\b(sc(\.exe)?\s+delete|remove-service)\s+[\"']?(tacticalrmm|tacticalagent|mesh\s*agent)",
)


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except ValueError:
        return default


def _list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(p.strip().lower() for p in value.split(",") if p.strip())


def _patterns(value: str | None) -> tuple[str, ...]:
    """Regex-Liste, getrennt durch ';;' (Kommas kommen in Regex vor)."""
    if not value:
        return ()
    return tuple(p.strip() for p in value.split(";;") if p.strip())


@dataclass(frozen=True)
class Settings:
    trmm_url: str
    trmm_api_key: str
    trmm_tls_verify: bool
    mcp_api_key: str
    read_only: bool = False
    protected_agents: tuple[str, ...] = ()
    blocked_command_patterns: tuple[str, ...] = DEFAULT_BLOCKED_COMMAND_PATTERNS
    max_timeout: int = 600
    max_output_chars: int = 30000

    def secret_values(self) -> tuple[str, ...]:
        """Werte, die in keiner Ausgabe und keinem Log auftauchen dürfen."""
        return tuple(v for v in (self.trmm_api_key, self.mcp_api_key) if v and len(v) >= 4)


def load_settings() -> Settings:
    env = os.environ
    return Settings(
        trmm_url=env.get("TRMM_URL", "").strip().rstrip("/"),
        trmm_api_key=env.get("TRMM_API_KEY", "").strip(),
        trmm_tls_verify=_bool(env.get("TRMM_TLS_VERIFY"), True),
        mcp_api_key=env.get("MCP_API_KEY", ""),
        read_only=_bool(env.get("TRMM_READ_ONLY"), False),
        protected_agents=_list(env.get("PROTECTED_AGENTS")),
        blocked_command_patterns=DEFAULT_BLOCKED_COMMAND_PATTERNS + _patterns(env.get("BLOCKED_COMMAND_PATTERNS")),
        max_timeout=min(3600, max(30, _int(env.get("MAX_TIMEOUT"), 600))),
        max_output_chars=max(2000, _int(env.get("MAX_OUTPUT_CHARS"), 30000)),
    )


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset() -> None:
    """Nur für Tests: Konfiguration beim nächsten Zugriff neu aus der Umgebung lesen."""
    global _settings
    _settings = None
