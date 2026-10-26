"""Konfiguration ausschliesslich über Umgebungsvariablen (siehe README).

Secrets (TRMM_API_KEY, MCP_API_KEY) kommen nur aus der Umgebung bzw. den
Portainer-Stack-Variablen und werden nie ins Image gebaut.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Grobe Notbremse gegen offensichtlich zerstörerische Befehle. Sie ersetzt nicht
# die confirm-Pflicht und ist KEINE Sicherheitsgrenze gegen jemanden, der das
# Token hat oder das Modell per Prompt-Injection steuert - die Sicherheitsgrenze
# sind MCP_ALLOW_EXEC (Default aus), confirm=true, TRMM_READ_ONLY und
# PROTECTED_AGENTS. Die Liste verhindert, dass ein Tippfehler oder eine falsch
# verstandene Anweisung eine Platte löscht, und fängt die gängigen
# Verschleierungen (encoded commands, Invoke-Expression, Download-Cradles,
# ^-Escapes, Flag-Reihenfolge). Gilt immer, zusätzlich zu
# BLOCKED_COMMAND_PATTERNS - per Env lässt sie sich nicht abschalten.
# Geprüft wird der Rohtext und normalisierte Varianten (siehe guard.normalized_variants).
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
    # rm -rf / in jeder Flag-Reihenfolge und Schreibweise (-rf, -fr, -r -f, --recursive --force,
    # --no-preserve-root dazwischen); Ziel "/" oder "/*"
    r"\brm\s+(?=(?:-\S+\s+)*-(?:[a-z]*r|-recursive))(?=(?:-\S+\s+)*-(?:[a-z]*f|-force))(?:-\S+\s+)+[\"']?/[\"']?(\s|$|\*)",
    r"\bmkfs(\.[a-z0-9]+)?\b",
    r"\bdd\s+[^|]*\bof=/dev/(sd|nvme|hd|vd|xvd)",
    # Remove-Item ... -Recurse ... C:\ in beliebiger Reihenfolge (Pfad vor oder nach den Flags)
    r"\bremove-item\b(?=[^|;]*\s-r[a-z]*\b)[^|;]*\s[\"']?[a-z]:\\?\*?[\"']?(\s|$|;|\|)",
    # Get-ChildItem C:\ | Remove-Item (Laufwerkswurzel über die Pipeline löschen)
    r"\b(get-childitem|gci|ls|dir)\b[^|]*\s[\"']?[a-z]:\\?\*?[\"']?(\s[^|]*)?\|\s*(remove-item|ri|rm|del|erase)\b",
    r"\b(rd|rmdir)\s+/s\s+(/q\s+)?[\"']?[a-z]:\\?[\"']?(\s|$)",          # rd /s C:\
    r"\bdel\s+(/[a-z]\s+)*[\"']?[a-z]:\\\*",                              # del C:\*
    r"tacticalagent.*unins|unins.*tacticalagent",                          # Agent nicht deinstallieren
    r"\b(sc(\.exe)?\s+delete|remove-service)\s+[\"']?(tacticalrmm|tacticalagent|mesh\s*agent)",
    # Verschleierung: encoded commands (-e/-ec/-enc/-EncodedCommand mit Base64) an powershell/pwsh
    r"\b(powershell|pwsh)(\.exe)?\b[^|;&]*\s-e(c|n[a-z]*)?\s+[\"']?[a-z0-9+/=]{16,}",
    r"(^|\s)-encodedcommand\b",
    # Verschleierung: Invoke-Expression / iex / [scriptblock]::Create (Code aus Strings ausführen)
    r"(^|[^\w-])(invoke-expression|iex)\b",
    r"\[scriptblock\]\s*::\s*create\s*\(",
    # Download-Cradles: Download direkt in eine Shell pipen oder als Befehlssubstitution ausführen
    r"\b(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b[^|]*\|\s*(iex|invoke-expression|sh|bash|zsh|dash|powershell|pwsh|cmd|python[0-9.]*|perl)\b",
    r"\b(sh|bash|zsh|dash|eval|source)\s+(-[a-z]+\s+)*[\"']?(\$\(|<\()\s*(curl|wget)\b",
    r"\b(downloadstring|downloadfile)\s*\(",
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
    # MCP_ALLOW_EXEC: ohne diesen Schalter sind Befehls- und Script-Ausführung
    # sowie das Anlegen von Scripts, Script-Checks und Script-Tasks deaktiviert.
    allow_exec: bool = False
    protected_agents: tuple[str, ...] = ()
    blocked_command_patterns: tuple[str, ...] = DEFAULT_BLOCKED_COMMAND_PATTERNS
    max_timeout: int = 600
    max_task_timeout: int = 14400
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
        mcp_api_key=env.get("MCP_API_KEY", "").strip(),
        read_only=_bool(env.get("TRMM_READ_ONLY"), False),
        allow_exec=_bool(env.get("MCP_ALLOW_EXEC"), False),
        protected_agents=_list(env.get("PROTECTED_AGENTS")),
        blocked_command_patterns=DEFAULT_BLOCKED_COMMAND_PATTERNS + _patterns(env.get("BLOCKED_COMMAND_PATTERNS")),
        max_timeout=min(3600, max(30, _int(env.get("MAX_TIMEOUT"), 600))),
        # Für Bibliotheks-Scripts und geplante Tasks: Tactical führt sie selbst aus, der MCP wartet nicht darauf.
        max_task_timeout=min(86400, max(600, _int(env.get("MAX_TASK_TIMEOUT"), 14400))),
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
