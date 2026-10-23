# tactical-mcp

MCP-Server für [Tactical RMM](https://github.com/amidaware/tacticalrmm). Läuft ausschliesslich als
Docker-Container (z.B. via Portainer) hinter einem Reverse-Proxy und wird als Custom Connector in
Claude genutzt. Kein lokaler Betrieb, kein stdio.

Damit lassen sich Agents auslesen (Inventar, Software, Dienste, Prozesse, Eventlogs, Checks, Tasks,
Windows-Updates, Alerts, Verlauf) und Probleme direkt beheben: Befehle in cmd, PowerShell oder bash,
Ad-hoc-Scripts, Scripts aus der Bibliothek, Dienste, Prozesse, Neustart, Updates.

## Sicherheit

- **Bearer-Token:** Ohne `MCP_API_KEY` (mindestens 32 Zeichen, wird getrimmt) startet der Server
  nicht. Jeder Request ohne gültiges `Authorization: Bearer <MCP_API_KEY>` bekommt 401 (auch
  `/healthz`). Konstantzeit-Vergleich.
- **confirm:** Alles, was auf einem Agent etwas ausführt oder ändert, läuft nur mit `confirm=true`.
  Ohne confirm kommt eine Vorschau (Agent, Client, Site, Status, Shell, Befehl bzw. Script-Code).
- **Code-Ausführung nur mit `MCP_ALLOW_EXEC=1`:** Standardmässig sind `trmm_run_command`,
  `trmm_run_script_code`, `trmm_run_script`, `trmm_save_script`, `trmm_add_script_check` und
  `trmm_add_monthly_script_task` deaktiviert und melden einen klaren Fehler. Das ist die eigentliche
  Sicherheitsgrenze gegen beliebige Code-Ausführung (Token-Diebstahl, Prompt-Injection) - der
  Schalter lässt sich nur serverseitig in den Stack-Variablen setzen. Dienste, Prozesse, Neustart,
  Updates, vorhandene Checks/Tasks ausführen, Wartungsmodus, Notizen und Alerts gehen auch ohne ihn.
- **Nur-Lese-Modus:** `TRMM_READ_ONLY=1` sperrt alle ausführenden und ändernden Tools.
- **Geschützte Agents:** `PROTECTED_AGENTS` (fnmatch-Muster auf Hostname oder Agent-ID), auf diesen
  wird nichts ausgeführt oder geändert, lesen geht weiterhin. Gilt auch für Policy-Ziele: ein
  Script-Check oder Task auf einer Policy wird abgelehnt, wenn die Policy auf einen geschützten Agent
  wirkt (direkt, über Site/Client oder als Default-Policy; aufgelöst über
  `/automation/policies/<id>/related/`, bewusst grosszügig). Lässt sich die Zuordnung nicht lesen,
  wird abgelehnt.
- **Keine Script-Updates:** `trmm_save_script` legt nur neue Scripts an. Bestehende Scripts können in
  Checks und Tasks geschützter Agents hängen; ein Update würde dort unbemerkt anderen Code ausführen.
  Änderungen an bestehenden Scripts nur direkt in Tactical.
- **Gesperrte Befehle:** Eine feste Liste blockiert offensichtlich zerstörerische Befehle (Formatieren,
  diskpart, Schattenkopien löschen, `Remove-Item -Recurse C:\`, `rm -rf /`, `mkfs`, Tactical-Agent
  deinstallieren usw.) in Befehlen, Ad-hoc-Code und Bibliotheks-Scripts, dazu die gängigen
  Verschleierungen: encoded commands (`-enc`/`-EncodedCommand`/`-e` mit Base64),
  `Invoke-Expression`/`iex`, `[scriptblock]::Create`, Download-Cradles (`curl`/`wget`/
  `Invoke-WebRequest` in eine Shell gepipt, `$(curl ...)`), `rm -r -f /` in jeder Flag-Reihenfolge,
  `Remove-Item` mit Pfad vor oder nach `-Recurse`, `Get-ChildItem C:\ | Remove-Item`. Geprüft wird der
  Rohtext und normalisierte Varianten (Kleinschreibung, Leerraum/Zeilenumbrüche, `^`- und
  Backtick-Escapes, String-Verkettung mit `+`). `BLOCKED_COMMAND_PATTERNS` ergänzt eigene Regex
  (getrennt durch `;;`); die feste Liste lässt sich nicht abschalten. Die Liste ist ein
  Tippfehler-/Komfortschutz, keine Sicherheitsgrenze - dafür sind `MCP_ALLOW_EXEC`, confirm,
  `PROTECTED_AGENTS` und die Tactical-Rolle da.
- **Agent-Schutz:** Dienst und Prozess des Tactical-/Mesh-Agents werden nicht gestoppt bzw. beendet.
- **Kein Löschen:** Keine Tools zum Löschen oder Deinstallieren von Agents, Clients, Sites oder Scripts.
- **Timeouts:** Ein Timeout bei einer Aktion wird als "Zustand unklar" gemeldet und nicht automatisch
  wiederholt. `MAX_TIMEOUT` begrenzt die Laufzeit pro Aufruf.
- **Schwärzung und Audit-Log:** Jeder Tool-Aufruf landet als JSON-Zeile auf stdout (Tool, Parameter,
  Status, Dauer). API-Keys erscheinen weder in Ausgaben noch in Logs. Im Log stehen von `env_vars`
  nur die Namen, `command`/`code`/`args`/`note` werden auf 200 Zeichen gekürzt und Inline-Secrets
  (`PASSWORD=...`, `-p ...`, `net user x ...` mit `password=`) maskiert; Parameter mit
  PASSWORD/TOKEN/SECRET/KEY im Namen werden ganz maskiert. Das Compose-File rotiert die Logs
  (`max-size`). Die Vorschau zeigt von Env-Variablen nur die Namen.
- Container läuft als Nicht-root, read-only Root-FS, ohne Capabilities, ohne Docker-Socket. Der
  Host-Port ist standardmässig nur auf `127.0.0.1` gebunden (`MCP_BIND_ADDR`).
  `security_opt` fehlt bewusst, weil Portainer es nur Admin-Benutzern erlaubt.

Zusätzlich protokolliert Tactical selbst jeden Befehl und jedes Script im Agent-Verlauf und im Audit-Log
unter dem Benutzer des API-Keys.

## Tools

Agents werden per Hostname (Gross-/Kleinschreibung egal, eindeutiger Teilstring reicht) oder Agent-ID
angegeben.

Lesen:

| Tool | Zweck |
|---|---|
| `trmm_version` | Version von tactical-mcp und Tactical RMM |
| `trmm_list_clients` | Clients mit Sites |
| `trmm_list_agents` | Agents, filterbar nach Client, Site, Status, Typ, Suchbegriff |
| `trmm_get_agent` | Details (OS, Hardware, Disks, IPs, Benutzer, Bootzeit, Checks, Custom Fields), optional WMI/Dienste |
| `trmm_ping_agent` | Live-Erreichbarkeit |
| `trmm_get_agent_software` | Installierte Software |
| `trmm_get_agent_services` | Windows-Dienste (live) |
| `trmm_get_agent_processes` | Prozesse nach RAM oder CPU |
| `trmm_get_event_log` | Eventlog System/Application/Security, filterbar |
| `trmm_get_agent_checks` | Checks mit Status und Ausgabe |
| `trmm_get_agent_tasks` | Automatisierte Tasks mit letztem Resultat |
| `trmm_get_windows_updates` | Updates aus dem letzten Scan |
| `trmm_list_alerts` | Alerts mit Filtern |
| `trmm_get_agent_history` | Zuletzt ausgeführte Befehle und Scripts |
| `trmm_get_agent_notes` | Notizen |
| `trmm_get_pending_actions` | Ausstehende Aktionen |
| `trmm_list_scripts` / `trmm_get_script` | Script-Bibliothek |
| `trmm_script_run_history` | Script-Läufe über alle Agents |

Ausführen und ändern (alle mit `confirm`):

| Tool | Zweck |
|---|---|
| `trmm_run_command` | Einzelner Befehl in cmd, PowerShell oder bash (`MCP_ALLOW_EXEC`) |
| `trmm_run_script_code` | Ad-hoc-Code (PowerShell, cmd, Python, Shell, Nushell, Deno) mit stdout/stderr/Exit-Code (`MCP_ALLOW_EXEC`) |
| `trmm_run_script` | Script aus der Bibliothek per ID oder Name (`MCP_ALLOW_EXEC`) |
| `trmm_service_action` | Dienst starten, stoppen, neu starten |
| `trmm_kill_process` | Prozess beenden |
| `trmm_reboot_agent` / `trmm_shutdown_agent` | Neustart / Herunterfahren |
| `trmm_recover_agent` | Mesh- bzw. Tactical-Agent-Verbindung reparieren |
| `trmm_scan_windows_updates` / `trmm_install_windows_updates` | Update-Scan bzw. genehmigte Updates installieren |
| `trmm_run_checks` / `trmm_run_task` | Checks bzw. Task sofort ausführen |
| `trmm_set_maintenance_mode` | Wartungsmodus |
| `trmm_add_agent_note` | Notiz anhängen |
| `trmm_alert_action` | Alert auflösen oder schlummern |

Konfigurieren (alle mit `confirm` und `MCP_ALLOW_EXEC`):

| Tool | Zweck |
|---|---|
| `trmm_save_script` | Neues Script in der Bibliothek anlegen (keine Updates bestehender Scripts) |
| `trmm_list_policies` | Automation-Policies auflisten (lesend) |
| `trmm_add_script_check` | Script Check auf einem Agent oder einer Policy anlegen |
| `trmm_add_monthly_script_task` | Monatlichen Script-Task auf einem Agent oder einer Policy anlegen |

## Konfiguration

| Variable | Pflicht | Beschreibung |
|---|---|---|
| `TRMM_URL` | ja | API-URL der Instanz, z.B. `https://api.rmm.example.com` |
| `TRMM_API_KEY` | ja | API-Key des Tactical-Benutzers für den MCP |
| `TRMM_TLS_VERIFY` | nein | Default `1` |
| `MCP_API_KEY` | ja | Bearer-Token für den Connector (`openssl rand -hex 32`, mindestens 32 Zeichen) |
| `TRMM_READ_ONLY` | nein | `1` = nur lesen |
| `MCP_ALLOW_EXEC` | nein | `1` = Befehle/Scripts ausführen und Scripts, Script-Checks, Script-Tasks anlegen; Default `0` (deaktiviert) |
| `PROTECTED_AGENTS` | nein | z.B. `srv-dc*,srv-rmm` (gilt auch für Policy-Ziele) |
| `BLOCKED_COMMAND_PATTERNS` | nein | Zusätzliche Regex, getrennt durch `;;` |
| `MAX_TIMEOUT` | nein | Obergrenze Sekunden pro Aufruf, Default 600 |
| `MAX_OUTPUT_CHARS` | nein | Ausgaben werden darüber gekürzt (Anfang und Ende bleiben), Default 30000 |
| `MCP_HOST_PORT` / `MCP_BIND_ADDR` | nein | Host-Port bzw. Bind-Adresse im Compose-File, Default `127.0.0.1:8428` |

Secrets nur über Env bzw. Portainer-Stack-Variablen, nie im Image. Vorlage: `.env.example`.

## Tactical-Benutzer und Rechte

Eigenen Benutzer (z.B. `mcp`) mit eigener Rolle anlegen, nicht den Admin verwenden. Unter
*Settings > Global Settings > API Keys* einen Key für diesen Benutzer erstellen (Ablaufdatum setzen).

Rechte der Rolle, die die Tools brauchen:

- Lesen: `can_list_clients`, `can_list_sites`, `can_list_agents`, `can_list_software`,
  `can_view_eventlogs`, `can_manage_procs` (Prozessliste), `can_manage_winsvcs` (Dienstliste),
  `can_list_checks`, `can_list_autotasks`, `can_manage_winupdates` (Update-Liste), `can_list_alerts`,
  `can_list_agent_history`, `can_list_notes`, `can_list_pendingactions`, `can_list_scripts`
- Ausführen: `can_send_cmd`, `can_run_scripts`, `can_reboot_agents`, `can_recover_agents`,
  `can_run_checks`, `can_run_autotasks`
- Ändern: `can_edit_agent` (Wartungsmodus), `can_manage_notes`, `can_manage_alerts`
- Nur für die konfigurierenden Tools (optional, nur vergeben, wenn sie gebraucht werden):
  `can_manage_scripts` (`trmm_save_script`), `can_manage_checks` (`trmm_add_script_check`),
  `can_manage_autotasks` (`trmm_add_monthly_script_task`), `can_list_automation_policies`
  (`trmm_list_policies` und die Policy-Prüfung gegen `PROTECTED_AGENTS`)

Nicht nötig und bewusst nicht vergeben: Agents deinstallieren/installieren/aktualisieren, Bulk-Aktionen,
Terminal/Web-Terminal, Registry, Server-Scripts, Core-Einstellungen, Benutzer, Rollen, API-Keys,
Clients/Sites/Policies verwalten. Ohne die optionalen Rechte liefert Tactical für die konfigurierenden
Tools 403 - das ist die zweite Schutzschicht neben `MCP_ALLOW_EXEC`. Mit "Nur bestimmte Clients/Sites"
in der Rolle lässt sich der Zugriff zusätzlich einschränken; für Server und Domänencontroller
`PROTECTED_AGENTS` setzen.

## Deployment

1. Stack in Portainer aus `docker-compose.yml` anlegen, Env-Variablen setzen.
2. Im Reverse-Proxy (z.B. Nginx Proxy Manager) einen Proxy-Host für die MCP-Domain auf
   `<Host-IP>:<MCP_HOST_PORT>` mit Let's-Encrypt-Zertifikat und "Force SSL" anlegen.
3. In Claude unter *Einstellungen > Connectors* einen Custom Connector mit
   `https://<mcp-domain>/mcp` hinzufügen, Authentifizierung per Bearer-Token (`MCP_API_KEY`).
4. `trmm_version` aufrufen, um Version und Verbindung zu prüfen.

## Versionierung und Build

Versionen kommen ausschliesslich aus Git-Tags. GitHub Actions führt bei jedem Push die Tests aus und baut
bei einer neuen Version (Datei `VERSION` bzw. Tag `vX.Y.Z`) das Image `ghcr.io/<owner>/tactical-mcp`
mit den Tags `X.Y.Z` und `latest`. Ohne Tag meldet der Server `dev-<kurzer Commit>`.

## Entwicklung

```
pip install -r requirements-dev.txt
pytest -q
```

Alle Tests laufen gegen gemockte APIs, nie gegen eine echte Instanz.

Getestet gegen die Tactical-RMM-API v1.x (Endpunkte unter `/agents/`, `/clients/`, `/scripts/`,
`/services/`, `/software/`, `/winupdate/`, `/checks/`, `/tasks/`, `/alerts/`, `/logs/`, `/core/`).
