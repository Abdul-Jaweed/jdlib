"""The ASGI entry point: ``uvicorn examples.enterprise.app.asgi:app``."""

from __future__ import annotations

from examples.enterprise.app.main import create_app

app = create_app()
