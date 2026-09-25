"""The application's own tables.

Importing this package is what registers them in `TenantBase.metadata`, and that metadata is
what the library's tenant migration creates and its RLS installer walks. The import is
load-bearing.
"""

from examples.enterprise.app.models.resources import Entity, Resource

__all__ = ["Entity", "Resource"]
