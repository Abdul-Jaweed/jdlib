"""Connector framework (successor Phase 6).

A connector is asynchronous throughout, declares what it can do, and refuses to open unless
it can verify the security context that authorized it covers the target it was given. The
policy extends the adapter-local reliability idiom this library already uses - validated
frozen config, injected clock, fail-closed exhaustion - and adds circuit breaking and
half-open recovery, which the reliability inventory recorded as genuinely absent.
"""

from jdlib.data.capabilities import ConnectorCapabilities
from jdlib.data.connector import AuthorizationRefusedError, DataConnector
from jdlib.data.contract import assert_connector_contract
from jdlib.data.errors import (
    CircuitOpenError,
    ConnectorError,
    ConnectorTimeoutError,
)
from jdlib.data.policy import ConnectionPolicy
from jdlib.data.postgres import PostgresConnector
from jdlib.data.registry import ConnectorRegistry

__all__ = [
    "AuthorizationRefusedError",
    "CircuitOpenError",
    "ConnectionPolicy",
    "ConnectorCapabilities",
    "ConnectorError",
    "ConnectorRegistry",
    "ConnectorTimeoutError",
    "DataConnector",
    "PostgresConnector",
    "assert_connector_contract",
]
