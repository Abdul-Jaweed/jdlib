---
guide: storage
authority: docs/jdlib/capabilities/storage.md
modules:
  - src/jdlib/storage/__init__.py
  - src/jdlib/storage/errors.py
  - src/jdlib/storage/keys.py
  - src/jdlib/storage/metadata.py
  - src/jdlib/storage/provider.py
  - src/jdlib/storage/s3.py
exports:
  - ObjectStorageProvider
  - S3ObjectStorage
  - StoredObject
  - ObjectMetadata
  - object_key
  - tenant_prefix
  - assert_object_storage_contract
example:
  - examples/enterprise/app/configuration/settings.py
test_files:
  - tests/integration/test_object_storage.py
---
# Object storage

> **Design authority:** [`docs/jdlib/capabilities/storage.md`](../capabilities/storage.md) — this guide is the developer-facing
> shape of that page, not a second authority for it. Where the two disagree, the authority page and
> the code win.

## What it is

Tenant-prefixed object storage: keys built by the library (`tenant_prefix`, `object_key`), a provider interface with an S3 implementation, and a contract test any implementation must pass.

## Why it exists

Object stores have no row-level security. The only thing standing between one tenant's bucket listing and another's objects is the key layout and the credentials -- so the key is built by the library, not by each call site.

## When to use it

For tenant-scoped blobs: uploads, exports, generated reports. Use it whenever an object belongs to a tenant and a wrong key would be a disclosure.

## When not to use it

For data that belongs in the database (it needs a transaction, a join or a constraint), and for anything a caller could address by a key they supplied.

## How it works

`object_key(tenant, ...)` builds a key under `tenant_prefix(tenant)`, so a path traversal or a missing tenant is a refused key (`InvalidObjectKeyError`) rather than a stray write. `S3ObjectStorage` implements `ObjectStorageProvider`; `assert_object_storage_contract` is the test suite an implementation must satisfy, which is what makes a second backend safe to add.

## Architecture

`storage/keys.py` (the layout), `storage/provider.py` (the interface and its contract), `storage/s3.py` (the implementation), `storage/metadata.py` (what is recorded about an object), `storage/errors.py` (the typed refusals).

## Example

The example configures storage through settings; the capability's own integration test drives the provider against a real store, and is the reference for a deployment's own smoke check.

## Security

The tenant is in the key, the key is built by the library, and an invalid key is refused before any I/O. A provider is expected to hand out tenant-scoped credentials where the store supports it -- the contract test asserts the behaviour, not the intention.

## Reliability

Provider errors are typed (`ObjectNotFoundError` vs a transport failure), so a missing object is a 404 and an outage is a 503. Uploads are addressed by the key the library built, so a retry cannot land in the wrong tenant's prefix.

## Observability

Operations record the key and the object's size and content type; never a signed URL, which is itself a credential.

## Audit

Access to an object that holds personal data is a privileged read: the audit vocabulary records it, with the key's tenant rather than the key itself where the key is sensitive.

## Configuration

Endpoint, bucket and credentials are configuration; the key layout is the library's, not a setting.

## Testing

`tests/integration/test_object_storage.py` runs the contract against a real store; a deployment should run the same contract against its own backend before trusting it.

## Common mistakes

Building a key by string concatenation; accepting a caller-supplied key; serving a signed URL through a log; assuming the store enforces tenancy because the application does.

## Production checklist

Use tenant-scoped credentials where the store allows it; keep objects private and serve through the application; run the storage contract test in your gate; and give each tenant's prefix a lifecycle rule rather than a manual purge.
