"""Schlanker Client für die Tactical-RMM-REST-API.

Auth über den Header X-API-KEY (API-Key eines eigenen Tactical-Benutzers).
Fehlermeldungen enthalten nie den Key oder andere Header.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .errors import TrmmApiError, UnclearStateError

logger = logging.getLogger("tactical_mcp")

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 60.0


class TrmmClient:
    def __init__(self, base_url: str, api_key: str, verify: bool = True, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-API-KEY": api_key, "Accept": "application/json"},
            verify=verify,
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        timeout: float | None = None,
        write: bool = False,
    ) -> Any:
        """Ruft path relativ zur API-Basis auf. timeout = Lese-Timeout in Sekunden.
        write=True: Bei Timeout ist unklar, ob die Aktion ausgeführt wurde."""
        if not path.startswith("/"):
            path = "/" + path
        t = httpx.Timeout(timeout or READ_TIMEOUT, connect=CONNECT_TIMEOUT)
        try:
            resp = await self._client.request(method, path, params=params, json=json, timeout=t)
        except httpx.ConnectTimeout:
            raise TrmmApiError("Tactical-API nicht erreichbar (Verbindungs-Timeout).") from None
        except httpx.TimeoutException:
            if write:
                raise UnclearStateError(
                    f"Timeout bei {method} {path}: Ob die Aktion auf dem Agent ausgeführt wurde, ist unklar. "
                    "Zuerst den Ist-Zustand prüfen (z.B. trmm_get_agent_history), nicht einfach wiederholen."
                ) from None
            raise TrmmApiError(f"Timeout bei {method} {path}.") from None
        except httpx.HTTPError as exc:
            raise TrmmApiError(f"Verbindungsfehler zur Tactical-API ({type(exc).__name__}).") from None

        if resp.status_code in (401, 403):
            raise TrmmApiError(
                f"Tactical-API verweigert den Zugriff ({resp.status_code}) bei {method} {path}. "
                "API-Key oder Rechte des MCP-Benutzers prüfen."
            )
        if resp.status_code == 404:
            raise TrmmApiError(f"Nicht gefunden (404): {method} {path}")
        if resp.status_code >= 400:
            detail = _short_error(resp)
            raise TrmmApiError(f"Tactical-API-Fehler {resp.status_code} bei {method} {path}: {detail}")
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, json: Any = None, **kw: Any) -> Any:
        return await self.request("POST", path, json=json, write=True, **kw)

    async def put(self, path: str, json: Any = None, **kw: Any) -> Any:
        return await self.request("PUT", path, json=json, write=True, **kw)

    async def patch(self, path: str, json: Any = None, *, write: bool = True, **kw: Any) -> Any:
        return await self.request("PATCH", path, json=json, write=write, **kw)

    async def delete(self, path: str, **kw: Any) -> Any:
        return await self.request("DELETE", path, write=True, **kw)


def _short_error(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        text = resp.text.strip()
        # Django-HTML-Fehlerseiten nicht durchreichen
        return "(keine Detailmeldung)" if text.startswith("<") else text[:300]
    if isinstance(data, str):
        return data[:300]
    if isinstance(data, dict):
        for k in ("detail", "error", "non_field_errors"):
            if k in data:
                return str(data[k])[:300]
        return str(data)[:300]
    return str(data)[:300]
