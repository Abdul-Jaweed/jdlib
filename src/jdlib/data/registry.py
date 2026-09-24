from __future__ import annotations

from typing import Any

from jdlib.data.contract import assert_connector_contract
from jdlib.data.errors import ConnectorError
from jdlib.security.tracing import TracerLike, security_span


class ConnectorRegistry:
    """The known connector types, validated when they are registered rather than when used.

    "Startup-validated" is the whole point: a connector whose interface is wrong, or whose
    methods block the event loop, is refused here - at the moment someone wires the
    application up - instead of failing under production load.
    """

    def __init__(self, *, tracer: TracerLike | None = None) -> None:
        self._types: dict[str, type] = {}
        self._tracer = tracer

    def register(self, connector: type) -> str:
        problems = assert_connector_contract(connector)
        if problems:
            raise ConnectorError(
                f"connector {getattr(connector, '__name__', connector)!r} does not satisfy the "
                "contract: " + "; ".join(problems)
            )
        try:
            declared = getattr(connector, "capabilities", None)
            name = getattr(declared, "name", None)
        except Exception as exc:
            raise ConnectorError(
                f"connector {getattr(connector, '__name__', connector)!r} declares no readable "
                f"capabilities: {type(exc).__name__}"
            ) from exc
        if not isinstance(name, str) or not name.strip():
            raise ConnectorError(
                f"connector {getattr(connector, '__name__', connector)!r} declares no name"
            )
        if name in self._types:
            raise ConnectorError(f"a connector named {name!r} is already registered")
        self._types[name] = connector
        return name

    def build(self, name: str, **kwargs: Any) -> Any:
        try:
            connector = self._types[name]
        except KeyError as exc:
            raise ConnectorError(
                f"no connector named {name!r} is registered; known: {sorted(self._types)}"
            ) from exc
        with security_span(
            self._tracer,
            "connector.acquire",
            attributes={"security.operation": "connector.acquire"},
        ) as span:
            span.set_attribute("security.backend", name)
            return connector(**kwargs)

    @property
    def names(self) -> list[str]:
        return sorted(self._types)
