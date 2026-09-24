"""Redaction of secret-shaped values (directive §3, §9, §17).

One canonical pattern set, used by

* error responses (``jdlib.security.responses``) so a message that quotes a
  header, a DSN or a query cannot disclose a credential, and
* audit metadata (``jdlib.security.audit``) so an operator cannot log a secret
  by accident.

Patterns are deliberately conservative: they only match shapes that are
unambiguously credentials, so ordinary operational text survives intact.
"""

from __future__ import annotations

import re

REDACTED = "[redacted]"

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PEM blocks (private keys, certificates)
    re.compile(r"-----BEGIN [A-Z ]{1,40}-----.*?-----END [A-Z ]{1,40}-----", re.DOTALL),
    # JWTs: three base64url segments starting with the standard header prefix
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    # any bearer credential
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # credentials embedded in a URL (database connection strings)
    re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^/\s:@]{1,64}:[^/\s@]{1,128}@"),
    # `password=...`, `secret: ...`, `api_key=...`, `token=...`
    re.compile(
        r"(?i)\b(api[_-]?key|client[_-]?secret|secret|password|passwd|pwd|token)"
        r"\b\s*[:=]\s*\S{3,}"
    ),
    # SQL statements and their bind values
    re.compile(
        r"(?i)\b(select|insert\s+into|update|delete\s+from|drop|alter|grant)\b"
        r".{0,200}?\b(from|into|set|table|where|privileges)\b"
    ),
    # stack frames
    re.compile(r"(?i)\bfile\s+\"[^\"]{1,200}\""),
    # fully-qualified policy names (internal policy detail)
    re.compile(r"\bresource\.[a-z_]{2,40}\.[a-z0-9]{2,40}\b"),
)

# Metadata keys whose *name* is disqualifying regardless of the value.
SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "connection_string",
        "credential",
        "credentials",
        "database_url",
        "dsn",
        "id_token",
        "password",
        "passwd",
        "private_key",
        "pwd",
        "refresh_token",
        "secret",
        "secret_key",
        "token",
    }
)

_SENSITIVE_SUFFIXES = ("_secret", "_password", "_token", "_key")

# A value that *is* a connection string: the host and database name are internal
# infrastructure detail too, so the whole value is redacted rather than only the
# credentials inside it. Inside a longer message the URL pattern above applies,
# which keeps the sentence useful while still removing the credential.
_WHOLE_VALUE_URL = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://\S+$")


def is_sensitive_key(key: str) -> bool:
    """Whether a metadata key names a secret by itself."""
    lowered = key.lower()
    return lowered in SENSITIVE_KEYS or lowered.endswith(_SENSITIVE_SUFFIXES)


def redact_text(text: str) -> str:
    """Replace every secret-shaped fragment in ``text``."""
    if _WHOLE_VALUE_URL.match(text.strip()):
        return REDACTED
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


__all__ = [
    "REDACTED",
    "SECRET_PATTERNS",
    "SENSITIVE_KEYS",
    "is_sensitive_key",
    "redact_text",
]
