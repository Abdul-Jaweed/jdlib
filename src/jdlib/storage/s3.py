from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from jdlib.resources.connection import ConnectionConfig
from jdlib.security.context import SecurityContext
from jdlib.storage.errors import (
    AuthorizationRefusedError,
    ObjectNotFoundError,
    ObjectStorageError,
)
from jdlib.storage.keys import object_key, tenant_prefix
from jdlib.storage.metadata import ObjectMetadata, StoredObject

CHUNK_SIZE = 8192
_NOT_FOUND = ("NoSuchKey", "404", "NoSuchBucket")


class S3ObjectStorage:
    """S3-compatible object storage: the one verified backend (ADR-5).

    The client is blocking, so every call is dispatched to a thread. That is the honest way to
    satisfy the async discipline ADR-14 asks for - the event loop is never blocked - rather
    than an asynchronous-looking wrapper around a blocking call.

    Keys are built in exactly one place and are always relative to the caller's tenant, so a
    key cannot name another tenant's object even if a caller tries.
    """

    def __init__(self, *, chunk_size: int = CHUNK_SIZE) -> None:
        self._chunk_size = chunk_size
        self._client: Any = None
        self._tenant_id: str | None = None
        self._bucket: str | None = None

    # -- lifecycle --------------------------------------------------------------------------

    async def open(self, *, target: ConnectionConfig, context: SecurityContext) -> None:
        tenant = context.require_tenant()
        if str(tenant.tenant_id) != target.tenant_id:
            raise AuthorizationRefusedError(
                "object storage: the authorized context is for tenant "
                f"{tenant.tenant_id}, but the target belongs to {target.tenant_id}"
            )
        endpoint, bucket, encoded = self._parse(target.target)
        access_key, secret_key = self._credentials(encoded)
        self._client = await asyncio.to_thread(self._build_client, endpoint, access_key, secret_key)
        self._tenant_id = str(tenant.tenant_id)
        self._bucket = bucket

    @asynccontextmanager
    async def opened(
        self, *, target: ConnectionConfig, context: SecurityContext
    ) -> AsyncIterator[S3ObjectStorage]:
        await self.open(target=target, context=context)
        try:
            yield self
        finally:
            await self.close()

    async def close(self) -> None:
        self._client = None
        self._tenant_id = None
        self._bucket = None

    async def health(self) -> bool:
        if self._client is None:
            return False
        try:
            await asyncio.to_thread(self._client.head_bucket, Bucket=self._bucket)
        except Exception:
            return False
        return True

    # -- operations -------------------------------------------------------------------------

    async def put(self, key: str, data: bytes, *, content_type: str | None = None) -> StoredObject:
        client, bucket, stored_key = self._ready(key)
        arguments: dict[str, Any] = {"Bucket": bucket, "Key": stored_key, "Body": data}
        if content_type is not None:
            arguments["ContentType"] = content_type
        try:
            response = await asyncio.to_thread(client.put_object, **arguments)
        except Exception as exc:
            raise ObjectStorageError(f"object storage: put failed for {key!r}") from exc
        return StoredObject(
            key=stored_key,
            size=len(data),
            etag=str(response.get("ETag", "")).strip('"'),
        )

    async def get(self, key: str) -> bytes:
        client, bucket, stored_key = self._ready(key)
        try:
            response = await asyncio.to_thread(client.get_object, Bucket=bucket, Key=stored_key)
            body = await asyncio.to_thread(response["Body"].read)
        except Exception as exc:
            if self._is_missing(exc):
                raise ObjectNotFoundError(f"object storage: no object at {key!r}") from exc
            raise ObjectStorageError(f"object storage: get failed for {key!r}") from exc
        return bytes(body)

    async def metadata(self, key: str) -> ObjectMetadata:
        client, bucket, stored_key = self._ready(key)
        try:
            head = await asyncio.to_thread(client.head_object, Bucket=bucket, Key=stored_key)
        except Exception as exc:
            if self._is_missing(exc):
                raise ObjectNotFoundError(f"object storage: no object at {key!r}") from exc
            raise ObjectStorageError(f"object storage: metadata failed for {key!r}") from exc
        return ObjectMetadata(
            key=stored_key,
            size=int(head.get("ContentLength", 0)),
            etag=str(head.get("ETag", "")).strip('"'),
            content_type=head.get("ContentType"),
            last_modified=head.get("LastModified"),
        )

    async def stream(self, key: str) -> AsyncIterator[bytes]:
        client, bucket, stored_key = self._ready(key)
        try:
            response = await asyncio.to_thread(client.get_object, Bucket=bucket, Key=stored_key)
        except Exception as exc:
            if self._is_missing(exc):
                raise ObjectNotFoundError(f"object storage: no object at {key!r}") from exc
            raise ObjectStorageError(f"object storage: stream failed for {key!r}") from exc
        body = response["Body"]
        while True:
            chunk = await asyncio.to_thread(body.read, self._chunk_size)
            if not chunk:
                return
            yield bytes(chunk)

    async def list(self, *, prefix: str = "") -> list[StoredObject]:
        if self._client is None or self._tenant_id is None:
            raise ObjectStorageError("object storage: list before open")
        scoped = tenant_prefix(self._tenant_id) + "/"
        if prefix:
            scoped = object_key(self._tenant_id, prefix.rstrip("/")) + "/"
        paginator = self._client.get_paginator("list_objects_v2")

        def drain() -> list[StoredObject]:
            found: list[StoredObject] = []
            for page in paginator.paginate(Bucket=self._bucket, Prefix=scoped):
                for item in page.get("Contents", []):
                    found.append(
                        StoredObject(
                            key=item["Key"],
                            size=int(item.get("Size", 0)),
                            etag=str(item.get("ETag", "")).strip('"'),
                        )
                    )
            return found

        return await asyncio.to_thread(drain)

    async def delete(self, key: str) -> None:
        client, bucket, stored_key = self._ready(key)
        response = await asyncio.to_thread(
            client.list_objects_v2, Bucket=bucket, Prefix=stored_key, MaxKeys=1
        )
        if not response.get("Contents"):
            raise ObjectNotFoundError(f"object storage: no object at {key!r} to delete")
        try:
            await asyncio.to_thread(client.delete_object, Bucket=bucket, Key=stored_key)
        except Exception as exc:
            raise ObjectStorageError(f"object storage: delete failed for {key!r}") from exc

    # -- internals --------------------------------------------------------------------------

    def _ready(self, key: str) -> tuple[Any, str, str]:
        if self._client is None or self._tenant_id is None or self._bucket is None:
            raise ObjectStorageError("object storage: the provider is not open")
        return self._client, self._bucket, object_key(self._tenant_id, key)

    @staticmethod
    def _is_missing(exc: Exception) -> bool:
        code = ""
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            code = str(response.get("Error", {}).get("Code", ""))
        return code in _NOT_FOUND or isinstance(exc, ObjectNotFoundError)

    @staticmethod
    def _parse(target: str) -> tuple[str, str, str]:
        """``endpoint#bucket#base64(access:secret)`` - the resolved target, never a stored DSN."""
        parts = target.split("#")
        if len(parts) != 3:
            raise ObjectStorageError(
                "object storage: the resolved target must be endpoint#bucket#credentials"
            )
        return parts[0], parts[1], parts[2]

    @staticmethod
    def _credentials(encoded: str) -> tuple[str, str]:
        try:
            decoded = base64.b64decode(encoded).decode()
        except Exception as exc:
            raise ObjectStorageError("object storage: credentials could not be decoded") from exc
        if ":" not in decoded:
            raise ObjectStorageError("object storage: credentials are malformed")
        access_key, _, secret_key = decoded.partition(":")
        return access_key, secret_key

    @staticmethod
    def _build_client(endpoint: str, access_key: str, secret_key: str) -> Any:
        try:
            import boto3  # type: ignore[import-untyped]
            from botocore.client import Config  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise ObjectStorageError(
                "the S3 backend needs the 's3' extra: pip install 'jdlib[s3]'"
            ) from exc
        return boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}),
        )
