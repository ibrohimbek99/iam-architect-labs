"""ASGI entry point: `uvicorn lab01.main:app`."""

from lab01.api import create_app_from_env

app = create_app_from_env()
