from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    timestamp_ms = int(time.time() * 1000)
    raw = bytearray(os.urandom(16))
    raw[0:6] = timestamp_ms.to_bytes(6, "big")
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(raw))
