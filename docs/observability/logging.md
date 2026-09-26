# Logging

The library emits structured records through one shape, so a log line is machine-readable without a
parser per module.

## The record

`jdlib.security.telemetry.security_log_record` builds the record; `safe_emit` writes it. The fields are
the request's identity and the event's meaning — request id, trace id, the outcome, the code — and
never the data the operation touched.

## The redaction floor

`jdlib.security.redaction.is_sensitive_key` and `redact_text` run over a record before it is emitted:

```python
from jdlib.security.redaction import is_sensitive_key, redact_text
```

* a key that looks like a secret (`password`, `token`, `authorization`, `secret`, `key`, …) is
  replaced, whatever its value;
* free text is scanned for credential-shaped substrings and redacted in place.

It is a **floor, not the design**: the design is that the value never qualified for the record in the
first place. The floor exists because a floor is what catches the case nobody thought of.

## The rule for application code

Log the *decision* and the *identifier*, not the payload. If a log line is the only place a value
appears, that value is in a log aggregator with different access control from your database — which is
a disclosure with extra steps.

## Where it is tested

`tests/unit/security/` for the redaction rules and the record's shape, including the cases that must
be redacted whatever they contain.
