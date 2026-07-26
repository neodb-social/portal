"""Runs the portal with uvicorn."""

from __future__ import annotations

import os

import uvicorn

from .app import create_app


def main() -> None:
    uvicorn.run(
        create_app(),
        host=os.environ.get("PORTAL_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORTAL_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("PORTAL_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )


if __name__ == "__main__":
    main()
