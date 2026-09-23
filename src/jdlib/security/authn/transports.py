"""HTTP transports for authentication adapters (requires the ``http`` extra).

Importing this module pulls ``httpx``; it is deliberately **not** re-exported
from :mod:`jdlib.security.authn`, so the core and the adapter packages stay
import-safe (spec #73, #74).

Behaviour that matters for security:

* every request has an explicit timeout (spec #78),
* response status codes are classified: 5xx/429/timeouts/connection failures
  are *transient* (:class:`TokenEndpointUnavailable`) so the provider's retry
  policy applies, while 4xx credential/policy failures are permanent
  (:class:`TokenAcquisitionError`) and are never retried (spec #76) — an
  invalid client must not be hammered,
* response bodies are never included in exceptions or logs: a token endpoint
  response can contain credentials, so only the status code is reported.

Composition: a transport is bound to one endpoint. The provider supplies the
form and headers; the transport owns the URL, the HTTP client and the timeout.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta

import httpx

from jdlib.security.authn.provider import TokenAcquisitionError, TokenEndpointUnavailable

DEFAULT_TIMEOUT = timedelta(seconds=5)
_TRANSIENT_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_INSECURE_PREFIX_ERROR = "endpoint must use https (http is allowed only for localhost)"


def _require_secure(url: str) -> None:
    allowed = (
        url.startswith("https://")
        or url.startswith("http://localhost")
        or url.startswith("http://127.0.0.1")
    )
    if not allowed:
        raise ValueError(_INSECURE_PREFIX_ERROR)


class HttpJwksFetcher:
    """Fetch a JWKS document over HTTP(S) from a fixed URL."""

    def __init__(
        self,
        *,
        url: str,
        timeout: timedelta = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        _require_secure(url)
        self._url = url
        self._timeout = timeout
        self._client = client

    async def __call__(self, url: str | None = None) -> Mapping[str, object]:
        target = url or self._url
        _require_secure(target)
        if self._client is not None:
            response = await self._client.get(target, timeout=self._timeout.total_seconds())
        else:
            async with httpx.AsyncClient() as client:
                response = await client.get(target, timeout=self._timeout.total_seconds())
        response.raise_for_status()
        document: object = response.json()
        if not isinstance(document, Mapping):
            raise ValueError("JWKS document must be a JSON object")
        return document


class HttpTokenFetcher:
    """Perform an OAuth2 token request against a fixed endpoint."""

    def __init__(
        self,
        *,
        endpoint: str,
        timeout: timedelta = DEFAULT_TIMEOUT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        _require_secure(endpoint)
        self._endpoint = endpoint
        self._timeout = timeout
        self._client = client

    async def __call__(
        self, form: Mapping[str, str], headers: Mapping[str, str]
    ) -> Mapping[str, object]:
        try:
            if self._client is not None:
                response = await self._client.post(
                    self._endpoint,
                    data=dict(form),
                    headers=dict(headers),
                    timeout=self._timeout.total_seconds(),
                )
            else:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        self._endpoint,
                        data=dict(form),
                        headers=dict(headers),
                        timeout=self._timeout.total_seconds(),
                    )
        except httpx.TimeoutException as exc:
            raise TokenEndpointUnavailable("token endpoint timed out") from exc
        except httpx.TransportError as exc:
            raise TokenEndpointUnavailable("token endpoint unreachable") from exc
        if response.status_code in _TRANSIENT_STATUS:
            raise TokenEndpointUnavailable(f"token endpoint returned {response.status_code}")
        if response.status_code >= 400:
            # Body deliberately omitted: error responses may echo credentials.
            raise TokenAcquisitionError(
                f"token endpoint rejected the request with {response.status_code}"
            )
        document: object = response.json()
        if not isinstance(document, Mapping):
            raise TokenAcquisitionError("token endpoint returned a non-object response")
        return document


__all__ = ["DEFAULT_TIMEOUT", "HttpJwksFetcher", "HttpTokenFetcher"]
