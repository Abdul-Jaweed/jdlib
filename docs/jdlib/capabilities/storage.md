---
capability: storage
namespace: jdlib.storage
errors_module: jdlib.storage.errors
modules:
  - src/jdlib/storage/errors.py
  - src/jdlib/storage/keys.py
  - src/jdlib/storage/metadata.py
  - src/jdlib/storage/provider.py
  - src/jdlib/storage/s3.py
exports:
  - ObjectMetadata
  - ObjectStorageProvider
  - S3ObjectStorage
  - StoredObject
  - object_key
  - tenant_prefix
refusals:
  - AuthorizationRefusedError
  - InvalidObjectKeyError
  - ObjectNotFoundError
  - ObjectStorageError
test_files:
  - tests/integration/test_object_storage.py
test_functions: 8
---
# Object storage: one verified backend, tenant-scoped keys

## What it is

A provider protocol and exactly one backend that satisfies it, with keys built in one place and
always relative to the caller's tenant:

```python
storage = S3ObjectStorage()
async with storage.opened(target=config, context=context) as objects:
    stored = await objects.put("reports/q1.txt", b"...", content_type="text/plain")
    async for chunk in objects.stream("reports/q1.txt"):
        ...
```

## The decisions that carry weight

**Six hostile keys are refused rather than repaired** - a parent segment, an absolute path, an
empty key, a separator another SDK might normalise. Silently repairing a key is how one tenant's
write lands in another tenant's prefix. The cross-tenant case is tested as *invisibility*: tenant
B neither lists nor fetches tenant A's object.

**One backend, exported; the others absent.** A provider class in the public surface is a claim
that it works, so Google Cloud Storage and Azure Blob have no module and no export, and a test
asserts their absence.

**The client is blocking and every call is dispatched to a thread.** That is the honest way to
meet the async discipline rather than an async-looking wrapper around a blocking call.

## Evidence

8 test functions across `tests/integration/test_object_storage.py`, run with the project gate:

```bash
.venv/Scripts/python.exe -m pytest tests/integration/test_object_storage.py -q
```

Parametrized cases expand these functions further; the counts here are
functions, which is what the documentation check verifies.

## Limits

No presigned URLs, no multipart upload, no server-side encryption configuration: each is a
decision the application makes with its own bucket policy, and none is invented here.
