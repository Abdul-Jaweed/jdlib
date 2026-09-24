from __future__ import annotations

from typing import Final

REDACTED: Final = "[REDACTED]"


def redact(value: object) -> str:
    """Render the presence of a secret without its content.

    One helper rather than a per-callsite format string: there is then a single thing to
    review when the rules change. Never returns anything derived from the value, including
    its length or a prefix.
    """
    return REDACTED
