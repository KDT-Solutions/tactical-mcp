"""Gemeinsame Fehlerklassen. Meldungen sind für den Client bestimmt und
enthalten nie Header, Tokens oder Passwörter."""


class TrmmMcpError(Exception):
    """Basisklasse für erwartete Fehler mit Klartext-Meldung."""


class TrmmApiError(TrmmMcpError):
    pass


class GuardError(TrmmMcpError):
    """Aktion durch Schutzregeln blockiert oder Eingabe unzulässig."""


class UnclearStateError(TrmmMcpError):
    """Timeout während eines Schreibvorgangs: Ob die Aktion ausgeführt wurde, ist unbekannt."""
