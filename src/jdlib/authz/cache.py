from __future__ import annotations

from typing import Any


class AuthzCache:
    def __init__(self) -> None:
        self._dirty = False
        self._memo: dict[Any, Any] = {}

    def invalidate(self) -> None:
        self._dirty = True
        self._memo.clear()

    def get(self, key: Any) -> Any | None:
        return None if self._dirty else self._memo.get(key)

    def put(self, key: Any, value: Any) -> None:
        self._memo[key] = value
