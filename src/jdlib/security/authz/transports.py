"""HTTP transport for the Cerbos adapter (requires the ``http`` extra).

Deliberately separate from :mod:`jdlib.security.authz`, which stays import-safe
(spec #73, #74). Any non-2xx response raises, and the adapter turns that into a
denied, degraded decision — the transport itself never decides anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta

import httpx

DEFAULT_TIMEOUT = timedelta(seconds=2)


class HttpCerbosTransport:
    """POST a CheckResources payload to Cerbos and return the parsed body."""

    def __init__(
        self,
        *,
        timeout: timedelta = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._timeout = timeout
        self._client = client

    async def __call__(
        self, url: str, payload: Mapping[str, object], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        if not url.startswith("https://") and not url.startswith(
            ("http://localhost", "http://127.0.0.1")
        ):
            raise ValueError("cerbos must be reached over https (localhost is allowed)")
        try:
            if self._client is not None:
                response = await self._client.post(
                    url,
                    json=dict(payload),
                    headers=dict(headers),
                    timeout=self._timeout.total_seconds(),
                )
            else:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        url,
                        json=dict(payload),
                        headers=dict(headers),
                        timeout=self._timeout.total_seconds(),
                    )
        except httpx.TimeoutException as exc:
            raise TimeoutError("cerbos request timed out") from exc
        except httpx.TransportError as exc:
            raise ConnectionError("cerbos is unreachable") from exc
        if response.status_code >= 400:
            # Body omitted: policy error payloads can carry request attributes.
            raise RuntimeError(f"cerbos returned {response.status_code}")
        document: object = response.json()
        if not isinstance(document, Mapping):
            raise ValueError("cerbos returned a non-object response")
        return document


__all__ = ["DEFAULT_TIMEOUT", "HttpCerbosTransport"]
