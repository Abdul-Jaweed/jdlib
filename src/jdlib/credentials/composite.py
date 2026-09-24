from __future__ import annotations

from collections.abc import Iterable

from jdlib.credentials.errors import CredentialUnavailableError
from jdlib.persistence.secrets import SecretProvider

ABSENCE: tuple[type[BaseException], ...] = (KeyError, CredentialUnavailableError)


class CompositeSecretProvider:
    """Try providers in declared order.

    Falls through only on absence. A provider that fails for any other reason stops the chain
    and the failure is reported: degrading to a later provider on an outage would mean an
    outage silently resolves a different credential than the one configured, which is the
    class of behaviour this programme rejects.
    """

    def __init__(self, providers: Iterable[SecretProvider]) -> None:
        self._providers = list(providers)

    def resolve(self, handle: str) -> str:
        for provider in self._providers:
            try:
                return provider.resolve(handle)
            except ABSENCE:
                continue
            except Exception as exc:
                raise CredentialUnavailableError(
                    f"credential provider failed for handle {handle}: {type(exc).__name__}"
                ) from exc
        raise CredentialUnavailableError(f"no provider holds a credential for handle {handle}")
