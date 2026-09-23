import pytest
from pydantic import SecretStr, ValidationError

from jdlib.config import ContextConfig, ResolverConfig, ResolverName, RlsConfig, TenancyConfig


def test_signing_key_is_required():
    with pytest.raises(ValidationError):
        ContextConfig()


def test_defaults():
    config = TenancyConfig(context=ContextConfig(signing_key="s3cret"))
    assert config.context.envelope_ttl.total_seconds() == 300
    assert config.context.operator_ttl.total_seconds() == 1800
    assert config.context.allow_test_contexts is False
    assert config.resolvers.order == [
        ResolverName.JWT_CLAIM,
        ResolverName.SUBDOMAIN,
        ResolverName.PATH,
        ResolverName.HEADER,
        ResolverName.API_KEY,
    ]
    assert config.resolvers.path_prefix == "/t/"
    assert config.resolvers.header_name == "X-Tenant-Slug"
    assert config.resolvers.jwt_claim == "tid"
    assert config.resolvers.base_domain is None


def test_env_parsing(monkeypatch):
    monkeypatch.setenv("JDLIB_CONTEXT__SIGNING_KEY", "env-key")
    monkeypatch.setenv("JDLIB_RESOLVERS__ORDER", '["header","path"]')
    monkeypatch.setenv("JDLIB_RESOLVERS__BASE_DOMAIN", "app.example.com")
    config = TenancyConfig()
    assert config.context.signing_key.get_secret_value() == "env-key"
    assert config.resolvers.order == [ResolverName.HEADER, ResolverName.PATH]
    assert config.resolvers.base_domain == "app.example.com"


def test_path_prefix_must_be_non_empty_and_absolute():
    with pytest.raises(ValidationError):
        ResolverConfig(path_prefix="")
    with pytest.raises(ValidationError):
        ResolverConfig(path_prefix="t/")
    assert ResolverConfig(path_prefix="/tenants/").path_prefix == "/tenants/"


def test_secret_is_not_leaked_in_repr():
    config = TenancyConfig(context=ContextConfig(signing_key="top-secret"))
    assert "top-secret" not in repr(config)
    assert isinstance(config.context.signing_key, SecretStr)


def test_rls_defaults_to_disabled():
    config = TenancyConfig(context=ContextConfig(signing_key="s3cret"))
    assert config.rls.enabled is False
    assert config.rls.app_role is None
    explicit = TenancyConfig(
        context=ContextConfig(signing_key="s3cret"),
        rls=RlsConfig(enabled=True, app_role="jdlib_app"),
    )
    assert explicit.rls.enabled is True
    assert explicit.rls.app_role == "jdlib_app"
