"""S3 object storage against a real MinIO (successor Phase 9). RED first.

One verified backend (ADR-5), and the ones that are not verified are not exported at all: a
provider class that ships without a passing contract suite is a promise the library has not
kept, so the last test here asserts they are absent rather than merely discouraged.

Two safety properties, both tested as attacks:

* a key cannot escape its tenant prefix - ``..``, a leading slash, an empty segment and a
  separator-injected key are all refused, because a key is the only thing standing between one
  tenant's objects and another's;
* the provider refuses to open on an unauthorized context, the same way a connector does.

The endpoint and credentials arrive through section 4's hydration, never from a stored DSN.
"""

from __future__ import annotations

import uuid

import pytest
from testcontainers.core.container import DockerContainer

from jdlib.context import Principal, PrincipalKind, TenantContext
from jdlib.control.enums import PlacementStrategy
from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import AuthMethod, SecurityContext, security_context_scope
from jdlib.storage.errors import AuthorizationRefusedError, ObjectNotFoundError, ObjectStorageError
from jdlib.storage.s3 import S3ObjectStorage

TENANT_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")
ACCESS_KEY = "jdlib-test-access"
SECRET_KEY = "jdlib-test-secret"  # noqa: S105 - a throwaway credential for a throwaway container
BUCKET = "jdlib-test"


@pytest.fixture(scope="module")
def endpoint() -> str:
    """A real MinIO, with the test bucket already created.

    The bucket is created here rather than in a separate fixture so that every test which
    asks for an endpoint gets a usable one: a fixture nobody requests is a fixture that never
    ran, which is how the first version of this file failed.
    """
    import time

    import boto3
    from botocore.client import Config

    with DockerContainer("minio/minio:latest") as container:
        container.with_exposed_ports(9000)
        container.with_env("MINIO_ROOT_USER", ACCESS_KEY)
        container.with_env("MINIO_ROOT_PASSWORD", SECRET_KEY)
        container.with_command("server /data")
        container.start()
        url = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(9000)}"
        client = boto3.client(
            "s3",
            endpoint_url=url,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}),
        )
        deadline = time.monotonic() + 90
        while True:
            try:
                client.create_bucket(Bucket=BUCKET)
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        yield url


def _context(tenant_id: uuid.UUID = TENANT_ID) -> SecurityContext:
    principal = Principal(kind=PrincipalKind.USER, id=uuid.uuid4())
    tenant = TenantContext(
        tenant_id=tenant_id,
        tenant_slug="acme",
        strategy=PlacementStrategy.SHARED,
        principal=principal,
        request_id="req-1",
        correlation_id="corr-1",
        trace_id=None,
    )
    return SecurityContext.from_tenant_context(tenant=tenant, auth_method=AuthMethod.SERVICE)


def _target(endpoint: str, tenant_id: uuid.UUID = TENANT_ID) -> ConnectionConfig:
    import base64

    payload = base64.b64encode(f"{ACCESS_KEY}:{SECRET_KEY}".encode()).decode()
    return ConnectionConfig(
        handle="objstore-tenant-acme",
        target=f"{endpoint}#{BUCKET}#{payload}",
        credential_version="1",
        tenant_id=str(tenant_id),
    )


async def test_a_live_put_and_get_round_trip(endpoint) -> None:
    storage = S3ObjectStorage()
    body = b"the quick brown fox"

    with security_context_scope(_context()):
        async with storage.opened(target=_target(endpoint), context=_context()):
            stored = await storage.put("reports/q1.txt", body, content_type="text/plain")
            fetched = await storage.get("reports/q1.txt")

    assert fetched == body
    assert stored.key.endswith("reports/q1.txt")
    assert stored.size == len(body)
    assert stored.etag


async def test_metadata_is_reported_without_downloading(endpoint) -> None:
    storage = S3ObjectStorage()

    with security_context_scope(_context()):
        async with storage.opened(target=_target(endpoint), context=_context()):
            await storage.put("reports/meta.txt", b"abc", content_type="text/plain")
            metadata = await storage.metadata("reports/meta.txt")

    assert metadata.size == 3
    assert metadata.content_type == "text/plain"
    assert metadata.key.endswith("reports/meta.txt")


async def test_a_stream_reassembles_the_stored_bytes(endpoint) -> None:
    storage = S3ObjectStorage()
    body = b"x" * 10_000

    with security_context_scope(_context()):
        async with storage.opened(target=_target(endpoint), context=_context()):
            await storage.put("big/blob.bin", body)
            chunks = [chunk async for chunk in storage.stream("big/blob.bin")]

    assert b"".join(chunks) == body
    assert len(chunks) > 1, "a stream must actually stream"


async def test_delete_removes_the_object(endpoint) -> None:
    storage = S3ObjectStorage()

    with security_context_scope(_context()):
        async with storage.opened(target=_target(endpoint), context=_context()):
            await storage.put("reports/gone.txt", b"bye")
            await storage.delete("reports/gone.txt")
            with pytest.raises(ObjectNotFoundError):
                await storage.get("reports/gone.txt")


async def test_objects_are_tenant_scoped_and_invisible_across_tenants(endpoint) -> None:
    storage = S3ObjectStorage()

    with security_context_scope(_context(TENANT_ID)):
        async with storage.opened(target=_target(endpoint, TENANT_ID), context=_context(TENANT_ID)):
            await storage.put("shared-name.txt", b"tenant-a-secret")

    with security_context_scope(_context(OTHER_TENANT_ID)):
        async with storage.opened(
            target=_target(endpoint, OTHER_TENANT_ID), context=_context(OTHER_TENANT_ID)
        ):
            listed = [item.key for item in await storage.list(prefix="")]

    assert not any("shared-name.txt" in key for key in listed), listed

    with security_context_scope(_context(OTHER_TENANT_ID)):
        async with storage.opened(
            target=_target(endpoint, OTHER_TENANT_ID), context=_context(OTHER_TENANT_ID)
        ):
            with pytest.raises(ObjectNotFoundError):
                await storage.get("shared-name.txt")


@pytest.mark.parametrize(
    "hostile",
    ["../other-tenant/secret", "/etc/passwd", "a/../../b", "", "tenants/../..", "..%2f..%2fetc"],
)
async def test_a_key_cannot_escape_its_tenant_prefix(endpoint, hostile) -> None:
    storage = S3ObjectStorage()

    with security_context_scope(_context()):
        async with storage.opened(target=_target(endpoint), context=_context()):
            with pytest.raises((ObjectStorageError, ValueError)):
                await storage.put(hostile, b"x")
            with pytest.raises((ObjectStorageError, ValueError)):
                await storage.get(hostile)


async def test_the_provider_refuses_to_open_on_an_unauthorized_context(endpoint) -> None:
    storage = S3ObjectStorage()

    with pytest.raises(AuthorizationRefusedError):
        await storage.open(target=_target(endpoint, TENANT_ID), context=_context(OTHER_TENANT_ID))


def test_no_unverified_provider_is_exported() -> None:
    """ADR-5: a provider class ships only with a passing contract suite."""
    import jdlib.storage as storage

    exported = " ".join(storage.__all__).lower()
    for unverified in ("gcs", "azure", "blob", "google"):
        assert unverified not in exported, unverified
    for module in ("jdlib.storage.gcs", "jdlib.storage.azure"):
        with pytest.raises(ModuleNotFoundError):
            __import__(module)
