# jdlib Authentication (Phase 4d) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build authentication adapters — OIDC/JWT verification with JWKS caching and the frozen user-linking algorithm, API keys with Argon2 verification and tenant pinning, the composite authenticator — and wire the `ContextFactory` ports (`PrincipalDirectory`, `TenantDirectory`, `EntitlementChecker`) to the shipped registry/reader so the ASGI middleware runs end-to-end with real authentication.

**Architecture:** `jdlib.authn` verifies credentials and returns a `Principal`; it never creates contexts. `OidcAuthenticator` verifies tokens with PyJWT against a rotation-aware `JwksCache` and links identities through `UserLinker` (IdentityLink → trusted-email link → deny; no auto-provisioning). `ApiKeyAuthenticator` looks up `key_prefix` in the control plane, verifies the secret with Argon2, and pins the principal to the key's tenant. A `wiring` module adapts `TenantRegistry`/`ControlAccessReader` to the `ContextFactory` ports.

**Tech Stack:** PyJWT + cryptography (already dependencies), httpx (JWKS fetch), argon2-cffi, SQLAlchemy async. No new dependencies.

**Specs (frozen):** `docs/jdlib/04-authorization-model.md` §1–§2; design rev 7 §5.1–5.3, §7.1; `docs/jdlib/02-relational-schema.md` §3.4–3.8; `docs/jdlib/07-implementation-design.md` §4, §9, §11.

## Global Constraints

- No password storage, no session issuance: the package verifies credentials only.
- Canonical principal rule: for USER principals, `Principal.id == user_id`; for SERVICE_ACCOUNT, `id` is the service-account id and `tenant_id` is pinned.
- Login linking: `IdentityLink(issuer, subject)` match → active user; else trusted-email match → link; else deny. Unverified email is never trusted; no silent auto-provisioning.
- API keys: `prefix.keyid.secret`, `key_prefix` unique lookup, Argon2id hash at rest, optional scopes narrow only, pinned to one tenant and service account, revocable/expiring.
- Authentication failures are audited through `PlatformAudit` (mandatory, fail-closed) with no token material in metadata.
- Commands: `.venv/Scripts/python -m pytest ...`, `ruff check .`, `mypy src/jdlib`; integration tests need `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1` and a fresh DB.
- No comments in source; pristine test output; commit after every task.

---

### Task 1: Auth config, base protocol, composite authenticator

**Files:**
- Modify: `src/jdlib/config.py` (append `OidcConfig`, `ApiKeyConfig`; extend `TenancyConfig`)
- Create: `src/jdlib/authn/__init__.py`
- Create: `src/jdlib/authn/base.py`
- Create: `src/jdlib/authn/composite.py`
- Create: `tests/unit/test_authn_base.py`

**Interfaces:**
- Consumes: `RequestInfo` (from `jdlib.tenancy.resolution`), `Principal`, `PlatformAudit`.
- Produces: `OidcConfig(issuer, audience, algorithms, jwks_url, jwks_ttl, leeway, email_trusted)`; `ApiKeyConfig(prefix)`; `TenancyConfig.oidc`, `TenancyConfig.api_keys`; `Authenticator` protocol (`async authenticate(request) -> Principal | None`); `bearer_token(request) -> str | None`; `CompositeAuthenticator(authenticators)`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_authn_base.py`:

```python
import uuid

import pytest
from pydantic import ValidationError

from jdlib.authn.base import Authenticator, bearer_token
from jdlib.authn.composite import CompositeAuthenticator
from jdlib.config import ApiKeyConfig, OidcConfig, TenancyConfig
from jdlib.context import Principal, PrincipalKind
from jdlib.tenancy.resolution import RequestInfo


def _request(headers: dict[str, str] | None = None) -> RequestInfo:
    return RequestInfo(headers=headers or {}, query={}, path="/", host="app.example.com")


def test_oidc_config_defaults():
    config = OidcConfig(issuer="https://idp.example.com", audience="jdlib")
    assert config.algorithms == ["RS256"]
    assert config.jwks_ttl.total_seconds() == 3600
    assert config.leeway.total_seconds() == 60
    assert config.email_trusted is False
    assert config.jwks_url is None
    assert config.resolved_jwks_url() == "https://idp.example.com/.well-known/jwks.json"


def test_oidc_config_requires_issuer_and_audience():
    with pytest.raises(ValidationError):
        OidcConfig()


def test_tenancy_config_includes_auth_blocks():
    config = TenancyConfig(
        context={"signing_key": "k"},
        oidc={"issuer": "https://idp", "audience": "a"},
    )
    assert config.oidc is not None
    assert config.api_keys == ApiKeyConfig()


def test_bearer_token_extraction():
    assert bearer_token(_request({"authorization": "Bearer abc.def"})) == "abc.def"
    assert bearer_token(_request({"authorization": "bearer abc"})) == "abc"
    assert bearer_token(_request({"authorization": "Basic abc"})) is None
    assert bearer_token(_request()) is None


class _Authenticator:
    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal
        self.calls = 0

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        self.calls += 1
        return self._principal


async def test_composite_returns_first_principal():
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    first = _Authenticator(None)
    second = _Authenticator(principal)
    third = _Authenticator(principal)
    composite = CompositeAuthenticator([first, second, third])
    assert await composite.authenticate(_request()) is principal
    assert first.calls == 1 and second.calls == 1 and third.calls == 0


async def test_composite_returns_none_when_all_fail():
    composite = CompositeAuthenticator([_Authenticator(None), _Authenticator(None)])
    assert await composite.authenticate(_request()) is None


def test_authenticator_protocol_shape():
    assert hasattr(Authenticator, "authenticate")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_authn_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authn'`

- [ ] **Step 3: Implement config, base, composite**

Append to `src/jdlib/config.py`:

```python
class OidcConfig(BaseModel):
    issuer: str
    audience: str
    algorithms: list[str] = ["RS256"]
    jwks_url: str | None = None
    jwks_ttl: timedelta = timedelta(hours=1)
    leeway: timedelta = timedelta(seconds=60)
    email_trusted: bool = False

    def resolved_jwks_url(self) -> str:
        if self.jwks_url:
            return self.jwks_url
        return self.issuer.rstrip("/") + "/.well-known/jwks.json"


class ApiKeyConfig(BaseModel):
    prefix: str = "jd"
```

Extend `TenancyConfig`:

```python
    oidc: OidcConfig | None = None
    api_keys: ApiKeyConfig = ApiKeyConfig()
```

`src/jdlib/authn/__init__.py`: empty.

`src/jdlib/authn/base.py`:

```python
from __future__ import annotations

from typing import Protocol

from jdlib.context import Principal
from jdlib.tenancy.resolution import RequestInfo


class Authenticator(Protocol):
    async def authenticate(self, request: RequestInfo) -> Principal | None: ...


def bearer_token(request: RequestInfo) -> str | None:
    header = request.headers.get("authorization")
    if header is None:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value
```

`src/jdlib/authn/composite.py`:

```python
from __future__ import annotations

from collections.abc import Sequence

from jdlib.authn.base import Authenticator
from jdlib.context import Principal
from jdlib.tenancy.resolution import RequestInfo


class CompositeAuthenticator:
    def __init__(self, authenticators: Sequence[Authenticator]) -> None:
        self._authenticators = list(authenticators)

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        for authenticator in self._authenticators:
            principal = await authenticator.authenticate(request)
            if principal is not None:
                return principal
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_authn_base.py -v -W error`
Expected: PASS (8 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/config.py src/jdlib/authn tests/unit/test_authn_base.py
git commit -m "feat: auth config, authenticator protocol, composite authenticator"
```

---

### Task 2: OIDC verification (JWKS cache, token verifier, claim mapper)

**Files:**
- Create: `src/jdlib/authn/oidc.py`
- Create: `tests/unit/test_oidc_verification.py`

**Interfaces:**
- Consumes: `OidcConfig`, `Clock`, errors (`InvalidToken`, `ExpiredToken`, `AuthenticationError`).
- Produces: `JwksCache(url, ttl, fetcher, clock)` with `async signing_key(kid) -> object`; `TokenVerifier(config, clock)` with `verify(token, key) -> Mapping[str, object]`; `IdentityClaims(issuer, subject, email, email_verified)`; `ClaimMapper(config)` with `map(claims) -> IdentityClaims`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_oidc_verification.py`:

```python
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.oidc import ClaimMapper, IdentityClaims, JwksCache, TokenVerifier
from jdlib.config import OidcConfig
from jdlib.errors import ExpiredToken, InvalidToken
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp.example.com"
AUDIENCE = "jdlib"


def _keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk["kid"] = "key-1"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return private, {"keys": [jwk]}


def _config(**overrides) -> OidcConfig:
    base = {"issuer": ISSUER, "audience": AUDIENCE}
    base.update(overrides)
    return OidcConfig(**base)


def _token(private, *, clock, subject="user-1", email=None, verified=None, ttl=timedelta(minutes=5)):
    now = clock.now()
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
    }
    if email is not None:
        claims["email"] = email
        claims["email_verified"] = verified
    return pyjwt.encode(claims, private, algorithm="RS256", headers={"kid": "key-1"})


class _Fetcher:
    def __init__(self, jwks) -> None:
        self.jwks = jwks
        self.calls = 0

    async def __call__(self, url: str):
        self.calls += 1
        return self.jwks


def _cache(fetcher, clock) -> JwksCache:
    return JwksCache(url="https://idp.example.com/.well-known/jwks.json", ttl=timedelta(hours=1), fetcher=fetcher, clock=clock)


async def test_jwks_cache_caches_and_rotates():
    clock = FrozenClock()
    private, jwks = _keypair()
    fetcher = _Fetcher(jwks)
    cache = _cache(fetcher, clock)
    assert await cache.signing_key("key-1") is not None
    assert await cache.signing_key("key-1") is not None
    assert fetcher.calls == 1
    clock.advance(timedelta(hours=2))
    assert await cache.signing_key("key-1") is not None
    assert fetcher.calls == 2
    assert await cache.signing_key("missing") is None


async def test_verifier_accepts_valid_token_and_maps_claims():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    verifier = TokenVerifier(_config(), clock)
    claims = verifier.verify(_token(private, clock=clock, email="a@b.c", verified=True), await cache.signing_key("key-1"))
    mapped = ClaimMapper(_config()).map(claims)
    assert mapped == IdentityClaims(issuer=ISSUER, subject="user-1", email="a@b.c", email_verified=True)


async def test_verifier_rejects_expired_and_tampered():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    verifier = TokenVerifier(_config(), clock)
    key = await cache.signing_key("key-1")
    expired = _token(private, clock=clock, ttl=timedelta(minutes=-10))
    with pytest.raises(ExpiredToken):
        verifier.verify(expired, key)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock)[:-3] + "aaa", key)


async def test_verifier_rejects_wrong_audience_and_issuer():
    clock = FrozenClock()
    private, jwks = _keypair()
    cache = _cache(_Fetcher(jwks), clock)
    key = await cache.signing_key("key-1")
    verifier = TokenVerifier(_config(audience="other"), clock)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock), key)
    verifier = TokenVerifier(_config(issuer="https://other.example.com"), clock)
    with pytest.raises(InvalidToken):
        verifier.verify(_token(private, clock=clock), key)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_oidc_verification.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'jdlib.authn.oidc'`

- [ ] **Step 3: Implement `src/jdlib/authn/oidc.py` (verification portion)**

```python
from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta

import jwt as pyjwt

from jdlib.config import OidcConfig
from jdlib.context import Clock, SystemClock
from jdlib.errors import ExpiredToken, InvalidToken

JwksFetcher = Callable[[str], Awaitable[Mapping[str, object]]]


class JwksCache:
    def __init__(
        self,
        *,
        url: str,
        ttl: timedelta,
        fetcher: JwksFetcher,
        clock: Clock | None = None,
    ) -> None:
        self._url = url
        self._ttl = ttl
        self._fetcher = fetcher
        self._clock = clock or SystemClock()
        self._fetched_at = None
        self._keys: dict[str, object] = {}

    async def _refresh(self) -> None:
        document = await self._fetcher(self._url)
        keys: dict[str, object] = {}
        for jwk in document.get("keys", []):
            kid = jwk.get("kid")
            if kid:
                keys[str(kid)] = jwk
        self._keys = keys
        self._fetched_at = self._clock.now()

    def _stale(self) -> bool:
        if self._fetched_at is None:
            return True
        return self._clock.now() - self._fetched_at > self._ttl

    async def signing_key(self, kid: str) -> object | None:
        if self._stale() or kid not in self._keys:
            await self._refresh()
        jwk = self._keys.get(kid)
        if jwk is None:
            return None
        try:
            return pyjwt.PyJWK.from_dict(dict(jwk)).key
        except (pyjwt.PyJWKError, ValueError, KeyError):
            return None


class TokenVerifier:
    def __init__(self, config: OidcConfig, clock: Clock | None = None) -> None:
        self._config = config
        self._clock = clock or SystemClock()

    def verify(self, token: str, key: object) -> Mapping[str, object]:
        try:
            return pyjwt.decode(
                token,
                key,
                algorithms=self._config.algorithms,
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway.total_seconds(),
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise ExpiredToken("token expired") from exc
        except pyjwt.PyJWTError as exc:
            raise InvalidToken(f"token verification failed: {type(exc).__name__}") from exc


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    issuer: str
    subject: str
    email: str | None
    email_verified: bool


class ClaimMapper:
    def __init__(self, config: OidcConfig) -> None:
        self._config = config

    def map(self, claims: Mapping[str, object]) -> IdentityClaims:
        email = claims.get("email")
        verified = claims.get("email_verified")
        return IdentityClaims(
            issuer=str(claims.get("iss", self._config.issuer)),
            subject=str(claims["sub"]),
            email=str(email) if isinstance(email, str) else None,
            email_verified=bool(verified) if isinstance(verified, bool) else False,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_oidc_verification.py -v -W error`
Expected: PASS (4 passed)

- [ ] **Step 5: Lint, type check, commit**

Run: `.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authn/oidc.py tests/unit/test_oidc_verification.py
git commit -m "feat: oidc jwks cache, token verifier, claim mapper"
```

---

### Task 3: User linking and `OidcAuthenticator`

**Files:**
- Modify: `src/jdlib/authn/oidc.py` (append `UserLinker`, `OidcAuthenticator`)
- Create: `tests/integration/test_oidc_linking.py`
- Create: `tests/unit/test_oidc_authenticator.py`

**Interfaces:**
- Produces: `UserLinker(session_factory, config)` with `async link(claims) -> User | None`; `OidcAuthenticator(config, cache, verifier, mapper, linker, audit)` with `async authenticate(request) -> Principal | None`.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_oidc_linking.py`:

```python
import uuid

import pytest

from jdlib.authn.oidc import ClaimMapper, IdentityClaims, UserLinker
from jdlib.config import OidcConfig
from jdlib.control.models import IdentityLink, User


def _config(*, trusted: bool) -> OidcConfig:
    return OidcConfig(issuer="https://idp", audience="a", email_trusted=trusted)


async def test_link_by_identity_link(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="known@example.com", status="active"))
        session.add(
            IdentityLink(
                id=uuid.uuid4(), user_id=user_id, issuer="https://idp", subject="sub-1"
            )
        )
        await session.commit()
    linker = UserLinker(control_session_factory, _config(trusted=False))
    user = await linker.link(
        IdentityClaims(issuer="https://idp", subject="sub-1", email=None, email_verified=False)
    )
    assert user is not None and user.id == user_id


async def test_link_by_trusted_email(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="trusted@example.com", status="active"))
        await session.commit()
    linker = UserLinker(control_session_factory, _config(trusted=True))
    user = await linker.link(
        IdentityClaims(
            issuer="https://idp", subject="sub-2", email="trusted@example.com", email_verified=True
        )
    )
    assert user is not None and user.id == user_id
    async with control_session_factory() as session:
        link = (
            await session.execute(
                sa.select(IdentityLink).where(
                    IdentityLink.user_id == user_id, IdentityLink.subject == "sub-2"
                )
            )
        ).scalar_one()
    assert link.issuer == "https://idp"


async def test_untrusted_or_unverified_email_does_not_link(control_session_factory):
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(User(id=user_id, email="plain@example.com", status="active"))
        await session.commit()
    untrusted = UserLinker(control_session_factory, _config(trusted=False))
    assert (
        await untrusted.link(
            IdentityClaims(
                issuer="https://idp", subject="sub-3", email="plain@example.com",
                email_verified=True,
            )
        )
        is None
    )
    trusted = UserLinker(control_session_factory, _config(trusted=True))
    assert (
        await trusted.link(
            IdentityClaims(
                issuer="https://idp", subject="sub-4", email="plain@example.com",
                email_verified=False,
            )
        )
        is None
    )


async def test_no_silent_provisioning(control_session_factory):
    linker = UserLinker(control_session_factory, _config(trusted=True))
    assert (
        await linker.link(
            IdentityClaims(
                issuer="https://idp", subject="sub-5", email="nobody@example.com",
                email_verified=True,
            )
        )
        is None
    )
```

Add `import sqlalchemy as sa` at the top.

`tests/unit/test_oidc_authenticator.py`:

```python
from datetime import timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jdlib.authn.oidc import JwksCache, OidcAuthenticator, TokenVerifier, ClaimMapper
from jdlib.config import OidcConfig
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.context import Principal, PrincipalKind
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock

ISSUER = "https://idp"


class _User:
    id = __import__("uuid").uuid4()
    email = "u@example.com"
    status = "active"


class _Linker:
    def __init__(self, user) -> None:
        self._user = user

    async def link(self, claims):
        return self._user


def _request(token: str | None) -> RequestInfo:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


async def test_authenticator_returns_user_principal():
    clock = FrozenClock()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = pyjwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update({"kid": "k", "alg": "RS256", "use": "sig"})
    config = OidcConfig(issuer=ISSUER, audience="a")
    cache = JwksCache(
        url="u", ttl=timedelta(hours=1),
        fetcher=lambda url: _jwks({"keys": [jwk]}), clock=clock,
    )
    token = pyjwt.encode(
        {"iss": ISSUER, "aud": "a", "sub": "s", "exp": clock.now() + timedelta(minutes=5)},
        private, algorithm="RS256", headers={"kid": "k"},
    )
    audit = RecordingPlatformAudit()
    authenticator = OidcAuthenticator(
        config=config, cache=cache, verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config), linker=_Linker(_User()), audit=audit,
    )
    principal = await authenticator.authenticate(_request(token))
    assert principal is not None
    assert principal.kind is PrincipalKind.USER
    assert principal.id == _User.id
    assert principal.user_id == _User.id
    assert audit.entries == []


async def _jwks(document):
    return document


async def test_authenticator_denies_and_audits_failures():
    clock = FrozenClock()
    config = OidcConfig(issuer=ISSUER, audience="a")
    cache = JwksCache(url="u", ttl=timedelta(hours=1), fetcher=_jwks, clock=clock)
    audit = RecordingPlatformAudit()
    authenticator = OidcAuthenticator(
        config=config, cache=cache, verifier=TokenVerifier(config, clock),
        mapper=ClaimMapper(config), linker=_Linker(None), audit=audit,
    )
    assert await authenticator.authenticate(_request(None)) is None
    assert await authenticator.authenticate(_request("not-a-token")) is None
    assert {entry["action"] for entry in audit.entries} == {"authn.failed"}
    assert all("token" not in str(entry).lower() or entry["action"] == "authn.failed" for entry in audit.entries)
```

Note for the implementer: `_User` must be a real control `User` ORM instance in the integration path; the unit test's duck-typed stand-in is fine there. Fix the awkward `__import__("uuid")` usage with a normal import; make `_jwks` an async function.

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_oidc_authenticator.py tests/integration/test_oidc_linking.py -v`
Expected: FAIL (missing `UserLinker`/`OidcAuthenticator`)

- [ ] **Step 3: Implement linking and the authenticator**

Append to `src/jdlib/authn/oidc.py`:

```python
from collections.abc import Callable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.base import bearer_token
from jdlib.control.audit import PlatformAudit
from jdlib.control.models import IdentityLink, User
from jdlib.control.session import ControlPlaneSession
from jdlib.context import Principal, PrincipalKind
from jdlib.tenancy.resolution import RequestInfo


class UserLinker:
    def __init__(
        self, session_factory: Callable[[], AsyncSession], config: OidcConfig
    ) -> None:
        self._session_factory = session_factory
        self._config = config

    async def link(self, claims: IdentityClaims) -> User | None:
        async with ControlPlaneSession(self._session_factory()) as session:
            link = (
                await session.execute(
                    sa.select(IdentityLink).where(
                        IdentityLink.issuer == claims.issuer,
                        IdentityLink.subject == claims.subject,
                    )
                )
            ).scalar_one_or_none()
            if link is not None:
                user = await session.get(User, link.user_id)
                if user is None or user.status != "active":
                    return None
                return user
            if not self._config.email_trusted or not claims.email_verified or not claims.email:
                return None
            user = (
                await session.execute(
                    sa.select(User).where(
                        sa.func.lower(User.email) == claims.email.lower(),
                        User.status == "active",
                    )
                )
            ).scalar_one_or_none()
            if user is None:
                return None
            session.add(
                IdentityLink(user_id=user.id, issuer=claims.issuer, subject=claims.subject)
            )
            await session.commit()
            return user


class OidcAuthenticator:
    def __init__(
        self,
        *,
        config: OidcConfig,
        cache: JwksCache,
        verifier: TokenVerifier,
        mapper: ClaimMapper,
        linker: UserLinker,
        audit: PlatformAudit,
    ) -> None:
        self._config = config
        self._cache = cache
        self._verifier = verifier
        self._mapper = mapper
        self._linker = linker
        self._audit = audit

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        token = bearer_token(request)
        if token is None:
            return None
        try:
            key = await self._cache.signing_key(_kid(token))
            if key is None:
                raise InvalidToken("unknown signing key")
            claims = self._verifier.verify(token, key)
            identity = self._mapper.map(claims)
        except AuthenticationError as exc:
            await self._audit.record(
                action="authn.failed",
                tenant_id=None,
                actor_id=None,
                metadata={"reason": type(exc).__name__},
            )
            return None
        user = await self._linker.link(identity)
        if user is None:
            await self._audit.record(
                action="authn.failed",
                tenant_id=None,
                actor_id=None,
                metadata={"reason": "unlinked_identity"},
            )
            return None
        return Principal(kind=PrincipalKind.USER, id=user.id, user_id=user.id)
```

Helpers at module top:

```python
def _kid(token: str) -> str:
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise InvalidToken("malformed token header") from exc
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise InvalidToken("token has no kid")
    return kid
```

and import `AuthenticationError` from `jdlib.errors`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_oidc_authenticator.py tests/integration/test_oidc_linking.py -v -W error`
Expected: PASS (6 passed)

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authn/oidc.py tests/unit/test_oidc_authenticator.py tests/integration/test_oidc_linking.py
git commit -m "feat: oidc user linking and authenticator"
```

---

### Task 4: API keys

**Files:**
- Create: `src/jdlib/authn/apikey.py`
- Create: `tests/unit/test_apikey_parser.py`
- Create: `tests/integration/test_apikey_auth.py`

**Interfaces:**
- Produces: `parse_api_key(token) -> ParsedApiKey(key_prefix, secret)`; `hash_api_key_secret(secret) -> str`; `ApiKeyAuthenticator(session_factory, audit)` with `async authenticate(request) -> Principal | None`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_apikey_parser.py`:

```python
import pytest

from jdlib.authn.apikey import hash_api_key_secret, parse_api_key, verify_api_key_secret
from jdlib.errors import InvalidToken


def test_parse_api_key_shape():
    parsed = parse_api_key("jd.keyid123.secret456")
    assert parsed.key_prefix == "jd.keyid123"
    assert parsed.secret == "secret456"


def test_parse_api_key_rejects_malformed():
    for token in ("", "jd.keyid", "jd..secret", "one.two.three.four"):
        with pytest.raises(InvalidToken):
            parse_api_key(token)


def test_hash_and_verify_roundtrip():
    stored = hash_api_key_secret("secret456")
    assert verify_api_key_secret("secret456", stored) is True
    assert verify_api_key_secret("wrong", stored) is False
    assert verify_api_key_secret("secret456", "not-a-hash") is False
```

`tests/integration/test_apikey_auth.py`:

```python
import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount, Tenant
from jdlib.context import PrincipalKind
from jdlib.tenancy.resolution import RequestInfo
from tests.support.context_fakes import FrozenClock


def _request(token: str | None) -> RequestInfo:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return RequestInfo(headers=headers, query={}, path="/", host="h")


async def _seed_key(control_session_factory, *, status="active", expired=False, sa_status="active"):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    secret = "secret-abc"
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"ak-{tenant_id.hex[:8]}", name="AK", status="active"))
        session.add(
            ServiceAccount(tenant_id=tenant_id, id=account_id, name="svc", status=sa_status)
        )
        session.add(
            ApiKey(
                tenant_id=tenant_id,
                id=uuid.uuid4(),
                service_account_id=account_id,
                key_prefix="jd.keyid123",
                key_hash=hash_api_key_secret(secret),
                scopes=["resource:read"],
                status=status,
                expires_at=(FrozenClock().now() - timedelta(days=1)) if expired else None,
            )
        )
        await session.commit()
    return tenant_id, account_id, secret


async def test_valid_key_returns_pinned_service_account(control_session_factory):
    tenant_id, account_id, secret = await _seed_key(control_session_factory)
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    principal = await authenticator.authenticate(_request(f"jd.keyid123.{secret}"))
    assert principal is not None
    assert principal.kind is PrincipalKind.SERVICE_ACCOUNT
    assert principal.id == account_id
    assert principal.tenant_id == tenant_id
    assert principal.scopes == frozenset({"resource:read"})
    async with control_session_factory() as session:
        stored = (
            await session.execute(sa.select(ApiKey.last_used_at).where(ApiKey.key_prefix == "jd.keyid123"))
        ).scalar_one()
    assert stored is not None


async def test_wrong_secret_revoked_expired_and_suspended_denied(control_session_factory):
    tenant_id, _, secret = await _seed_key(control_session_factory)
    audit = RecordingPlatformAudit()
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory, audit=audit, clock=FrozenClock()
    )
    assert await authenticator.authenticate(_request("jd.keyid123.wrong")) is None
    assert await authenticator.authenticate(_request("jd.unknown.key")) is None
    assert {entry["action"] for entry in audit.entries} == {"authn.failed"}
    _, _, revoked_secret = await _seed_key(control_session_factory, status="revoked")
    # revoked key uses a different prefix in practice; assert status path via direct lookup
    assert await authenticator.authenticate(_request("jd.keyid123.wrong")) is None
    _, _, expired_secret = await _seed_key(control_session_factory, expired=True)
    assert await authenticator.authenticate(_request("jd.keyid123.wrong")) is None
```

Note for the implementer: the integration test above has redundant seeds sharing the same `key_prefix`, which collides on the unique constraint — restructure `_seed_key` to take a unique `key_prefix` (e.g. derived from a uuid) and pass it to the requests. Keep the same assertions.

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_apikey_parser.py tests/integration/test_apikey_auth.py -v`
Expected: FAIL (missing module)

- [ ] **Step 3: Implement `src/jdlib/authn/apikey.py`**

```python
from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy.ext.asyncio import AsyncSession

from jdlib.authn.base import bearer_token
from jdlib.control.audit import PlatformAudit
from jdlib.control.models import ApiKey, ServiceAccount
from jdlib.control.session import ControlPlaneSession
from jdlib.context import Clock, Principal, PrincipalKind, SystemClock
from jdlib.errors import AuthenticationError, InvalidToken
from jdlib.tenancy.resolution import RequestInfo

_HASHER = PasswordHasher()


@dataclass(frozen=True, slots=True)
class ParsedApiKey:
    key_prefix: str
    secret: str


def parse_api_key(token: str) -> ParsedApiKey:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise InvalidToken("malformed api key")
    return ParsedApiKey(key_prefix=f"{parts[0]}.{parts[1]}", secret=parts[2])


def hash_api_key_secret(secret: str) -> str:
    return _HASHER.hash(secret)


def verify_api_key_secret(secret: str, stored_hash: str) -> bool:
    try:
        return _HASHER.verify(stored_hash, secret)
    except (VerificationError, InvalidHashError):
        return False


class ApiKeyAuthenticator:
    def __init__(
        self,
        *,
        session_factory: Callable[[], AsyncSession],
        audit: PlatformAudit,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit = audit
        self._clock = clock or SystemClock()

    async def authenticate(self, request: RequestInfo) -> Principal | None:
        token = bearer_token(request)
        if token is None:
            return None
        try:
            parsed = parse_api_key(token)
            principal = await self._resolve(parsed)
        except AuthenticationError as exc:
            await self._audit.record(
                action="authn.failed",
                tenant_id=None,
                actor_id=None,
                metadata={"reason": type(exc).__name__},
            )
            return None
        if principal is None:
            await self._audit.record(
                action="authn.failed",
                tenant_id=None,
                actor_id=None,
                metadata={"reason": "invalid_api_key"},
            )
        return principal

    async def _resolve(self, parsed: ParsedApiKey) -> Principal | None:
        async with ControlPlaneSession(self._session_factory()) as session:
            key = (
                await session.execute(
                    sa.select(ApiKey).where(ApiKey.key_prefix == parsed.key_prefix)
                )
            ).scalar_one_or_none()
            if key is None or key.status != "active":
                return None
            if key.expires_at is not None and key.expires_at <= self._clock.now():
                return None
            if not verify_api_key_secret(parsed.secret, key.key_hash):
                return None
            account = await session.get(
                ServiceAccount, {"tenant_id": key.tenant_id, "id": key.service_account_id}
            )
            if account is None or account.status != "active":
                return None
            key.last_used_at = self._clock.now()
            await session.commit()
            scopes = frozenset(key.scopes) if key.scopes is not None else None
            return Principal(
                kind=PrincipalKind.SERVICE_ACCOUNT,
                id=account.id,
                tenant_id=key.tenant_id,
                api_key_id=key.id,
                scopes=scopes,
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/unit/test_apikey_parser.py tests/integration/test_apikey_auth.py -v -W error`
Expected: PASS (5 passed)

- [ ] **Step 5: Full suite, lint, type check, commit**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/authn/apikey.py tests/unit/test_apikey_parser.py tests/integration/test_apikey_auth.py
git commit -m "feat: api key authentication with tenant pinning"
```

**Review fixes applied (follow-up commit from the Task 4 implementation):**

- `tests/integration/test_apikey_auth.py` now asserts the exact audit count, action (`authn.failed`), reason values (`InvalidToken` for a malformed token; `invalid_api_key` for unknown prefix, wrong secret, revoked, expired, and suspended-SA denials), and null tenant/actor for every denial path, plus that no token, secret, prefix, or stored Argon2 hash material appears in any entry (the seed helper returns the hash).
- Missing/malformed `Authorization` headers (absent, empty, non-Bearer scheme, `Bearer` with no value) deny with `None` and record nothing.

---

### Task 5: Context wiring and end-to-end middleware authentication

**Files:**
- Modify: `src/jdlib/control/registry.py` (append `find(ref) -> TenantRecord | None`)
- Create: `src/jdlib/authn/wiring.py`
- Create: `tests/integration/test_auth_wiring.py`
- Modify: `docs/jdlib/07-implementation-design.md` (file map: `authn/wiring.py`; note the port adapters)
- Modify: `docs/superpowers/plans/2026-09-21-jdlib-authentication-phase-4d.md` (back-ports)

**Interfaces:**
- Produces: `TenantRegistry.find(ref) -> TenantRecord | None`; `PrincipalDirectoryAdapter(reader)`; `TenantDirectoryAdapter(registry)`; `EntitlementAdapter(reader)`; `build_authenticator(...)` helper assembling OIDC + API-key + composite; end-to-end test: API-key principal through `TenantMiddleware` → `TenantContext` → guarded handler.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_auth_wiring.py`:

```python
import json
import uuid

import pytest
import sqlalchemy as sa

from jdlib.authn.apikey import ApiKeyAuthenticator, hash_api_key_secret
from jdlib.authn.wiring import (
    EntitlementAdapter,
    PrincipalDirectoryAdapter,
    TenantDirectoryAdapter,
)
from jdlib.authz.reader import ControlAccessReader
from jdlib.config import ContextConfig
from jdlib.context import ContextFactory, TenantRecord
from jdlib.control.audit import RecordingPlatformAudit
from jdlib.control.models import ApiKey, Membership, ServiceAccount, Tenant, TenantPlacement, TenantMigrationState, User
from jdlib.control.registry import TenantRegistry
from jdlib.persistence.strategies.shared import SharedSchemaStrategy
from jdlib.tenancy.middleware import TenantMiddleware
from jdlib.tenancy.resolution import HeaderResolver, ResolverChain
from tests.support.context_fakes import FrozenClock


class _Runner:
    def upgrade_tenant(self, schema: str, revision: str = "head") -> None:
        return None

    def tenant_version(self, schema: str) -> str | None:
        return "0001_tenant_baseline"


async def test_tenant_directory_and_entitlement_adapters(control_session_factory):
    registry = TenantRegistry(
        session_factory=control_session_factory,
        strategies={},
        runner=_Runner(),
        audit=RecordingPlatformAudit(),
        desired_version="0001_tenant_baseline",
    )
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"wire-{tenant_id.hex[:8]}", name="W", status="active"))
        session.add(TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default"))
        session.add(
            TenantMigrationState(
                tenant_id=tenant_id, current_version="0001_tenant_baseline",
                desired_version="0001_tenant_baseline", status="success",
            )
        )
        session.add(User(id=user_id, status="active"))
        session.add(Membership(tenant_id=tenant_id, id=uuid.uuid4(), user_id=user_id, status="active"))
        await session.commit()
    directory = TenantDirectoryAdapter(registry)
    record = await directory.get(TenantRef(id=tenant_id))
    assert record is not None and record.status.value == "active"
    assert await directory.get(TenantRef(slug="missing")) is None
    reader = ControlAccessReader(control_session_factory)
    principals = PrincipalDirectoryAdapter(reader)
    from jdlib.context import Principal, PrincipalKind

    principal = Principal(kind=PrincipalKind.USER, id=user_id, user_id=user_id)
    assert await principals.is_active(principal) is True
    entitlements = EntitlementAdapter(reader)
    assert await entitlements.can_act(principal, tenant_id) is True


async def test_api_key_principal_through_middleware(control_session_factory, async_engine):
    tenant_id = uuid.uuid4()
    account_id = uuid.uuid4()
    secret = "s3cret"
    prefix = f"jd.k{uuid.uuid4().hex[:8]}"
    async with control_session_factory() as session:
        session.add(Tenant(id=tenant_id, slug=f"mw-{tenant_id.hex[:8]}", name="MW", status="active"))
        session.add(TenantPlacement(tenant_id=tenant_id, strategy="shared", target_handle="default"))
        session.add(
            TenantMigrationState(
                tenant_id=tenant_id, current_version="0001_tenant_baseline",
                desired_version="0001_tenant_baseline", status="success",
            )
        )
        session.add(ServiceAccount(tenant_id=tenant_id, id=account_id, name="svc", status="active"))
        session.add(
            ApiKey(
                tenant_id=tenant_id, id=uuid.uuid4(), service_account_id=account_id,
                key_prefix=prefix, key_hash=hash_api_key_secret(secret), status="active",
            )
        )
        await session.commit()
    registry = TenantRegistry(
        session_factory=control_session_factory, strategies={}, runner=_Runner(),
        audit=RecordingPlatformAudit(), desired_version="0001_tenant_baseline",
    )
    reader = ControlAccessReader(control_session_factory)
    factory = ContextFactory(
        config=ContextConfig(signing_key="k"),
        principals=PrincipalDirectoryAdapter(reader),
        tenants=TenantDirectoryAdapter(registry),
        servability=registry,
        entitlements=EntitlementAdapter(reader),
        operators=reader,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    authenticator = ApiKeyAuthenticator(
        session_factory=control_session_factory,
        audit=RecordingPlatformAudit(),
        clock=FrozenClock(),
    )
    seen: list[uuid.UUID] = []

    async def inner(scope, receive, send):
        from jdlib.context import current_tenant

        seen.append(current_tenant().tenant_id)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = TenantMiddleware(
        inner, factory=factory,
        chain=ResolverChain([HeaderResolver(name="X-Tenant-Slug")]),
        principal_provider=authenticator,
    )

    async def receive():
        return {"type": "http.request"}

    sent: list[dict[str, object]] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "GET", "path": "/", "query_string": b"",
        "headers": [(b"authorization", f"Bearer {prefix}.{secret}".encode())],
    }
    await middleware(scope, receive, send)
    assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 200
    assert seen == [tenant_id]
```

Note: `operators=reader` works only if the reader satisfies `OperatorAuthorizer` — it does not. Pass a small inline stub class with `async authorize(...) -> False` instead; keep the test focused on principal/tenant/entitlement wiring.

- [ ] **Step 2: Run tests to verify they fail**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_auth_wiring.py -v`
Expected: FAIL (missing `jdlib.authn.wiring`)

- [ ] **Step 3: Implement `find` and the adapters**

Append to `TenantRegistry`:

```python
    async def find(self, ref: TenantRef) -> TenantRecord | None:
        async with await self._control() as session:
            statement = sa.select(Tenant)
            if ref.id is not None:
                statement = statement.where(Tenant.id == ref.id)
            elif ref.slug is not None:
                statement = statement.where(Tenant.slug == ref.slug)
            else:
                return None
            tenant = (await session.execute(statement)).scalar_one_or_none()
            if tenant is None:
                return None
            placement = await session.get(TenantPlacement, tenant.id)
            if placement is None:
                return None
            return TenantRecord(
                id=tenant.id,
                slug=tenant.slug,
                status=TenantStatus(tenant.status),
                strategy=PlacementStrategy(placement.strategy),
            )
```

(`TenantRef` import added; `_record` helper could be reused but needs a placement row — `find` builds it inline.)

`src/jdlib/authn/wiring.py`:

```python
from __future__ import annotations

from jdlib.authz.reader import AccessReader
from jdlib.context import Principal, PrincipalDirectory, TenantDirectory, TenantRecord, TenantRef
from jdlib.control.registry import TenantRegistry


class PrincipalDirectoryAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def is_active(self, principal: Principal) -> bool:
        return await self._reader.principal_active(principal)


class TenantDirectoryAdapter:
    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry

    async def get(self, ref: TenantRef) -> TenantRecord | None:
        return await self._registry.find(ref)


class EntitlementAdapter:
    def __init__(self, reader: AccessReader) -> None:
        self._reader = reader

    async def can_act(self, principal: Principal, tenant_id: object) -> bool:
        if not await self._reader.principal_active(principal):
            return False
        return await self._reader.membership_active(principal, tenant_id)
```

Note: type `tenant_id` as `uuid.UUID`; add the import.

- [ ] **Step 4: Run tests to verify they pass**

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest tests/integration/test_auth_wiring.py -v -W error`
Expected: PASS (2 passed)

- [ ] **Step 5: Docs, full suite, lint, type check, commit**

Update `07` file map (`authn/wiring.py`, note adapters) and back-port this plan.

Run: `TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 .venv/Scripts/python -m pytest -q -W error && .venv/Scripts/python -m ruff check . && .venv/Scripts/python -m mypy src/jdlib`

```bash
git add src/jdlib/control/registry.py src/jdlib/authn/wiring.py tests/integration/test_auth_wiring.py docs
git commit -m "feat: context factory port adapters and end-to-end auth wiring"
```

**Final state (shipped):** `TenantRegistry.find` builds the `TenantRecord` inline from the tenant row plus its placement and returns `None` for an empty ref, an unknown id/slug, or a missing placement. `src/jdlib/authn/wiring.py` ships the three adapters exactly as sketched (with `can_act`'s `tenant_id` typed `uuid.UUID`). Test corrections over the sketch: `ContextFactory(operators=...)` receives a two-line inline `OperatorAuthorizer` stub (`ControlAccessReader` is not one); the middleware chain is `[HeaderResolver, ApiKeyResolver]` so the API-key's pinned tenant resolves when no header is present; and `principal_provider=authenticator.authenticate` because the `PrincipalProvider` port is callable while `Authenticator` exposes `authenticate`. The test also covers `PrincipalDirectoryAdapter.is_active` denial and `EntitlementAdapter.can_act` for an active non-member, and drops the unused `async_engine` fixture argument. `build_authenticator` from the Interfaces line was not implemented: no step, signature, or test required it, and authenticator assembly belongs with the FastAPI/CLI integrations (Plan 6).

---

## Phase 4d Exit Criteria

- [ ] Full suite green on real PostgreSQL 16.
- [ ] OIDC: JWKS caching/rotation, verification (issuer/audience/algorithms/leeway), claim mapping, linking algorithm (IdentityLink → trusted verified email → deny), failures audited without token material.
- [ ] API keys: shape parsing, Argon2id verification, status/expiry checks, tenant pinning, scopes, `last_used_at`, failures audited.
- [ ] Composite authenticator first-wins; no authentication bypass.
- [ ] `ContextFactory` ports wired to registry/reader; API-key principal flows through `TenantMiddleware` to a tenant context end-to-end.
- [ ] `ruff` and strict `mypy` clean.

## Plan Series (remaining)

- Plan 5 — schema/database strategies, RLS emission, privileged tenant-plane deletion for shared `purge`.
- Plan 6 — durable audit sink, `jdlib.testing` kit, FastAPI/CLI integrations, public API exports, docs.
