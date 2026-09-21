import uuid

from jdlib.config import ResolverConfig, ResolverName
from jdlib.context import Principal, PrincipalKind, TenantRef
from jdlib.tenancy.resolution import (
    ApiKeyResolver,
    HeaderResolver,
    JwtClaimResolver,
    PathResolver,
    RequestInfo,
    ResolverChain,
    SubdomainResolver,
    build_chain,
)

TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


def _request(
    *, headers: dict[str, str] | None = None, path: str = "/", host: str = "app.example.com",
    claims: dict[str, object] | None = None,
) -> RequestInfo:
    return RequestInfo(
        headers=headers or {}, query={}, path=path, host=host, claims=claims or {}
    )


async def test_jwt_claim_resolver_accepts_uuid_and_slug():
    resolver = JwtClaimResolver(claim="tid")
    assert await resolver.resolve(_request(claims={"tid": str(TENANT_ID)}), None) == TenantRef(
        id=TENANT_ID
    )
    assert await resolver.resolve(_request(claims={"tid": "acme"}), None) == TenantRef(slug="acme")
    assert await resolver.resolve(_request(), None) is None


async def test_subdomain_resolver():
    resolver = SubdomainResolver(base_domain="app.example.com")
    assert await resolver.resolve(_request(host="acme.app.example.com"), None) == TenantRef(
        slug="acme"
    )
    assert await resolver.resolve(_request(host="app.example.com"), None) is None
    assert await resolver.resolve(_request(host="evil.com"), None) is None
    assert await resolver.resolve(_request(host="ACME.app.example.com"), None) == TenantRef(
        slug="acme"
    )


async def test_path_resolver():
    resolver = PathResolver(prefix="/t/")
    assert await resolver.resolve(_request(path="/t/acme/invoices"), None) == TenantRef(slug="acme")
    assert await resolver.resolve(_request(path="/t/"), None) is None
    assert await resolver.resolve(_request(path="/other/acme"), None) is None


async def test_header_resolver_is_case_insensitive():
    resolver = HeaderResolver(name="X-Tenant-Slug")
    assert await resolver.resolve(_request(headers={"x-tenant-slug": "acme"}), None) == TenantRef(
        slug="acme"
    )
    assert await resolver.resolve(_request(), None) is None


async def test_api_key_resolver_uses_pinned_tenant():
    resolver = ApiKeyResolver()
    pinned = Principal(kind=PrincipalKind.SERVICE_ACCOUNT, id=uuid.uuid4(), tenant_id=TENANT_ID)
    assert await resolver.resolve(_request(), pinned) == TenantRef(id=TENANT_ID)
    assert await resolver.resolve(_request(), None) is None
    assert (
        await resolver.resolve(
            _request(), Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
        )
        is None
    )


async def test_chain_first_non_none_wins():
    chain = ResolverChain(
        [HeaderResolver(name="X-Tenant-Slug"), PathResolver(prefix="/t/")]
    )
    request = _request(headers={"x-tenant-slug": "from-header"}, path="/t/from-path")
    assert await chain.resolve(request, None) == TenantRef(slug="from-header")
    assert await ResolverChain([PathResolver(prefix="/t/")]).resolve(request, None) == TenantRef(
        slug="from-path"
    )
    assert await ResolverChain([]).resolve(request, None) is None


def test_build_chain_maps_config_and_skips_subdomain_without_base_domain():
    config = ResolverConfig(order=[ResolverName.SUBDOMAIN, ResolverName.HEADER])
    assert len(build_chain(config).resolvers) == 1
    config = ResolverConfig(
        order=[ResolverName.SUBDOMAIN, ResolverName.HEADER], base_domain="app.example.com"
    )
    assert len(build_chain(config).resolvers) == 2
