"""Runtime configuration, all from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    #: Public origin this service is reached at. The OAuth redirect is derived
    #: from it and must match what instances have registered, so it has to be
    #: the address users actually hit, not the bind address.
    base_url: str = "https://p.neodb.net"

    #: How long a pairing code stays valid. Short on purpose: a pending session
    #: is a credential waiting to happen.
    session_ttl: int = 900

    max_sessions: int = 10_000

    #: Sessions a single client may open per minute, to keep the store bounded.
    create_rate_per_minute: int = 20

    #: Optional app website registered alongside the device's own name, which
    #: the device itself supplies when it opens a session.
    website: str | None = None

    #: NeoDB's published instance list, refreshed in the background when a
    #: pairing code is generated. Set empty to pin the built-in list and make
    #: the service fetch nothing.
    servers_url: str = "https://neodb.net/servers.json"

    #: Floor between refresh attempts, seconds. The list changes on the order of
    #: months, so this only has to be small enough that a fresh deploy picks up
    #: a new instance promptly.
    servers_refresh_interval: int = 60

    #: Development escape hatch: permits http:// and private addresses, both of
    #: which are refused in normal operation to avoid becoming an SSRF proxy.
    allow_private_hosts: bool = False

    #: Sentry DSN. Metrics are only emitted when this is set.
    sentry_dsn: str | None = None
    sentry_environment: str | None = None
    sentry_traces_sample_rate: float = 0.0

    @property
    def redirect_uri(self) -> str:
        # Under /svc/ so that no pairing code can ever shadow it: codes live at
        # the root of the path space now.
        return f"{self.base_url.rstrip('/')}/svc/callback"

    def join_url(self, code: str) -> str:
        return f"{self.base_url.rstrip('/')}/{code}"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            base_url=os.environ.get("PORTAL_BASE_URL", cls.base_url).rstrip("/"),
            session_ttl=int(os.environ.get("PORTAL_SESSION_TTL", cls.session_ttl)),
            max_sessions=int(os.environ.get("PORTAL_MAX_SESSIONS", cls.max_sessions)),
            create_rate_per_minute=int(
                os.environ.get("PORTAL_CREATE_RATE", cls.create_rate_per_minute)
            ),
            website=os.environ.get("PORTAL_WEBSITE") or None,
            # Not `or cls.servers_url`: an explicitly empty value is how an
            # operator says "fetch nothing", and must not fall back to a URL.
            servers_url=os.environ.get("PORTAL_SERVERS_URL", cls.servers_url).strip(),
            servers_refresh_interval=int(
                os.environ.get("PORTAL_SERVERS_REFRESH", cls.servers_refresh_interval)
            ),
            allow_private_hosts=_flag("PORTAL_ALLOW_PRIVATE_HOSTS"),
            sentry_dsn=os.environ.get("SENTRY_DSN") or None,
            sentry_environment=os.environ.get("SENTRY_ENVIRONMENT") or None,
            sentry_traces_sample_rate=float(
                os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0") or 0
            ),
        )
