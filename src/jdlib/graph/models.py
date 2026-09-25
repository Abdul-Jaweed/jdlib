"""Graph identifiers as validated values (successor §16; directive §12–§13).

A statement's *values* are always bound as parameters, so the only text that reaches Cypher is
an identifier: a label, a relationship type, a property key, or one of the two property names
this library sets itself. That makes identifiers the whole injection surface, and this module is
where it is closed — by pattern (a name that needs backticks is refused) and by vocabulary (a
name nobody declared is refused).

The three types are distinct on purpose. A label and a relationship type are both strings, and
passing one where the other belongs is a bug the type checker can catch instead of the database.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from jdlib.graph.errors import GraphValidationError

#: Labels: PascalCase, like the model in the directive (`:User`, `:Resource`).
_LABEL = re.compile(r"[A-Z][A-Za-z0-9]{0,62}\Z")
#: Relationship types: UPPER_SNAKE, the convention every graph model uses (`:OWNS`).
_RELATIONSHIP_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,62}\Z")
#: Property keys: lower_snake, the same shape the SQL identifier policy allows.
_PROPERTY_KEY = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")


def _refuse(pattern: re.Pattern[str], value: object, what: str) -> str:
    """Refuse anything that is not a plain identifier — and do not echo what was offered.

    A refused value is attacker-controlled text; repeating it into a message that will be
    logged is how a newline or a control character gets a second life.
    """
    if not isinstance(value, str) or not pattern.match(value):
        raise GraphValidationError(f"{what} must be a plain identifier and was refused")
    return value


@dataclass(frozen=True, slots=True)
class Label:
    """A node label, validated at construction."""

    value: str

    def __post_init__(self) -> None:
        _refuse(_LABEL, self.value, "a node label")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RelationshipType:
    """A relationship type, validated at construction."""

    value: str

    def __post_init__(self) -> None:
        _refuse(_RELATIONSHIP_TYPE, self.value, "a relationship type")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PropertyKey:
    """A property key, validated at construction."""

    value: str

    def __post_init__(self) -> None:
        _refuse(_PROPERTY_KEY, self.value, "a property key")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class GraphVocabulary:
    """Which labels, relationship types and property keys exist in this deployment.

    Closed by construction: an identifier is obtained *through* the vocabulary, so a label the
    deployment never declared cannot reach a statement however the caller spells it. The
    declared names are validated by the same patterns, because a declaration is not a way
    around the rule.
    """

    labels: frozenset[str]
    relationship_types: frozenset[str]
    property_keys: frozenset[str]

    def __post_init__(self) -> None:
        for name in self.labels:
            Label(name)
        for name in self.relationship_types:
            RelationshipType(name)
        for name in self.property_keys:
            PropertyKey(name)

    def label(self, name: str) -> Label:
        if name not in self.labels:
            raise GraphValidationError("unknown node label: it is not in this vocabulary")
        return Label(name)

    def relationship_type(self, name: str) -> RelationshipType:
        if name not in self.relationship_types:
            raise GraphValidationError("unknown relationship type: it is not in this vocabulary")
        return RelationshipType(name)

    def property_key(self, name: str) -> PropertyKey:
        if name not in self.property_keys:
            raise GraphValidationError("unknown property key: it is not in this vocabulary")
        return PropertyKey(name)
