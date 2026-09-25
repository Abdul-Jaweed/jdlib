"""The ASGI entry point: ``uvicorn examples.minimal.app.asgi:app``."""

from __future__ import annotations

from examples.minimal.app.main import create_app

app = create_app()
