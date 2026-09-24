from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QueryDialect:
    """How one engine spells identifiers and bind parameters.

    Quoting is a dialect concern rather than a safety measure - safety comes from the
    identifier allowlist at parse time - but a dialect that quoted nothing would emit
    ambiguous SQL for a column named like a keyword, so quoting is not optional.
    """

    name: str = "generic"
    quote_char: str = '"'
    parameter_prefix: str = ":"

    def quote(self, identifier: str) -> str:
        escaped = identifier.replace(self.quote_char, self.quote_char * 2)
        return f"{self.quote_char}{escaped}{self.quote_char}"

    def placeholder(self, name: str) -> str:
        return f"{self.parameter_prefix}{name}"


@dataclass(frozen=True, slots=True)
class PostgresDialect(QueryDialect):
    name: str = "postgres"
    quote_char: str = '"'
    parameter_prefix: str = ":"


@dataclass(frozen=True, slots=True)
class MysqlDialect(QueryDialect):
    name: str = "mysql"
    quote_char: str = "`"
    parameter_prefix: str = ":"
