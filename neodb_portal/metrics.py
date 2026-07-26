"""
Counters for the three moments worth knowing about.

* `portal.request` -- a device asked for a pairing code.
* `portal.login`   -- a visitor was sent off to an instance to authorize.
* `portal.link`    -- a device collected an access token, so the pairing worked.

Together they answer the only questions this service raises: are people finding
it, and does the handshake actually complete? The gap between `request` and
`link` is the drop-off rate.

Reporting goes to Sentry when a DSN is configured, and nowhere otherwise. Nothing
here identifies a person: the instance host is recorded because it is useful for
spotting a broken server, and that is as specific as it gets. Codes, tokens and
usernames are never attached.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

REQUEST = "portal.request"
LOGIN = "portal.login"
LINK = "portal.link"


def instance_host(instance: str | None) -> str:
    """Bare hostname, or "unknown" -- never a full URL with a path."""
    if not instance:
        return "unknown"
    return urlparse(instance).hostname or "unknown"


class Metrics:
    """
    A counter sink. Does nothing at all unless Sentry is configured.

    Kept as an object rather than module-level calls so the app can be built with
    a stub in tests, and so a missing `sentry-sdk` is a non-event.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        environment: str | None = None,
        release: str | None = None,
        traces_sample_rate: float = 0.0,
    ) -> None:
        self.enabled = False
        self._counter = None

        if not dsn:
            logger.info("Sentry DSN not set; metrics disabled")
            return

        try:
            import sentry_sdk
            from sentry_sdk import metrics as sentry_metrics
        except ImportError:
            logger.warning("SENTRY_DSN is set but sentry-sdk is not installed")
            return

        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            release=release,
            traces_sample_rate=traces_sample_rate,
            # This service handles access tokens. Never let the SDK decide to
            # attach request bodies, headers or user identifiers to anything.
            send_default_pii=False,
            max_request_body_size="never",
        )
        self._counter = sentry_metrics.count
        self.enabled = True
        logger.info("Sentry metrics enabled")

    def count(self, name: str, **attributes: str) -> None:
        """Adds one to `name`. Never raises: telemetry must not break a sign-in."""
        if not self.enabled or self._counter is None:
            return
        try:
            self._counter(name, 1, attributes=attributes or None)
        except Exception:  # pragma: no cover - defensive
            logger.warning("could not record metric %s", name, exc_info=True)

    # -- the three events --------------------------------------------------

    def request(self) -> None:
        """A device opened a pairing session."""
        self.count(REQUEST)

    def login(self, instance: str | None) -> None:
        """A visitor was redirected to an instance's authorization page."""
        self.count(LOGIN, instance=instance_host(instance))

    def link(self, instance: str | None) -> None:
        """A device collected the access token; the pairing is complete."""
        self.count(LINK, instance=instance_host(instance))
