from __future__ import annotations

from enum import StrEnum


class DeprovisionMode(StrEnum):
    ARCHIVE = "archive"
    PURGE = "purge"
    DESTROY = "destroy"
