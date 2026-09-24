"""Compliance surface (directive §9.1, §9.2).

The control registry and the model behind it. Importing this namespace pulls no
optional dependency and imports nothing from the persistence layer, so a posture
report over a configuration can be produced without a database.

Additions to this layer are additive by construction: the security core's public
surface is pinned by an exact-equality test, so new compliance API lives in this
submodule rather than in ``jdlib.security``.
"""

from jdlib.security.compliance.controls import (
    CONTROL_REGISTRY,
    Control,
    ControlCategory,
    ControlFramework,
    ControlMapping,
    ImplementationStatus,
    VerificationMethod,
    control_by_id,
    controls_for_framework,
    frameworks_in_use,
)

__all__ = [
    "CONTROL_REGISTRY",
    "Control",
    "ControlCategory",
    "ControlFramework",
    "ControlMapping",
    "ImplementationStatus",
    "VerificationMethod",
    "control_by_id",
    "controls_for_framework",
    "frameworks_in_use",
]
