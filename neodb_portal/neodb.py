"""
The NeoDB side of the handshake: app registration, authorization, token exchange.

NeoDB exposes the Mastodon-compatible application API, so a client registers
itself with `POST /api/v1/apps` and then runs an ordinary authorization-code
flow against `/oauth/authorize` and `/oauth/token`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import httpx

logger = logging.getLogger(__name__)

#: One row of the instance picker: the host to submit, a display name, and a
#: short note. Kept a plain dict because the templates render it directly.
Instance = dict[str, str]

#: Public instances listed in NeoDB's own documentation (docs/servers.json).
#: Offered as suggestions; any other host can be typed in. This is the seed and
#: the floor: `InstanceDirectory` refreshes from the published list at runtime,
#: and falls back to exactly this if it never manages to.
KNOWN_INSTANCES: list[Instance] = [
    {"host": "neodb.social", "name": "NeoDB", "note": "Flagship instance · zh, en"},
    {
        "host": "eggplant.place",
        "name": "NeoDB experimental",
        "note": "Development build · en",
    },
]

OAUTH_SCOPES = "read write"

#: Registered app names end up on the instance's consent screen, so they are
#: attacker-supplied text shown to a human. Keep them short and printable.
MAX_CLIENT_NAME = 64


class NeoDBError(Exception):
    """Raised when an instance cannot be used or refuses a request."""


def clean_client_name(value: str) -> str:
    """
    Normalizes a caller-supplied app name, or raises.

    The name is what the phone's owner reads on the consent screen ("<name>
    wants to access your account"), so it has to survive being rendered by an
    instance we do not control: no control characters, no newlines to fake extra
    lines of text with, and a length that cannot push the real prompt off screen.
    """
    name = " ".join(value.split())
    if not name:
        raise NeoDBError("Please give the device a name.")
    if not name.isprintable():
        raise NeoDBError("That client name contains characters that are not allowed.")
    if len(name) > MAX_CLIENT_NAME:
        raise NeoDBError(f"Client names are limited to {MAX_CLIENT_NAME} characters.")
    return name


@dataclass(frozen=True)
class AppCredentials:
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class TokenGrant:
    """
    What `/oauth/token` handed back.

    NeoDB answers with the access token, its type and its scopes, and nothing
    else: its tokens do not expire and it issues no refresh token, so a grant
    ends only when someone revokes it. Everything past the access token is
    therefore optional, and passed on to the device as-is for the sake of
    servers that do send it -- the portal is out of the picture by then.
    """

    access_token: str
    refresh_token: str | None = None
    token_type: str | None = None
    scope: str | None = None
    expires_in: int | None = None


def normalize_instance(value: str, *, allow_insecure: bool = False) -> str:
    """
    Turns whatever the user typed into `https://host`, or raises.

    Accepts "neodb.social", "https://neodb.social/", and pasted deep links.
    """
    text = (value or "").strip()
    if not text:
        raise NeoDBError("Please enter a server address.")

    if "://" not in text:
        text = "https://" + text

    parsed = urlparse(text)
    if parsed.scheme not in ("https", "http"):
        raise NeoDBError("Only https addresses are supported.")
    if parsed.scheme == "http" and not allow_insecure:
        raise NeoDBError("Only https addresses are supported.")
    if not parsed.hostname:
        raise NeoDBError("That does not look like a server address.")

    host = parsed.hostname.lower()
    if "." not in host and host != "localhost":
        raise NeoDBError("That does not look like a server address.")

    try:
        port = parsed.port
    except ValueError as exc:
        # urlparse defers the port until it is asked for, and then raises rather
        # than returning None, so "host:notaport" gets this far looking valid.
        # Left unhandled it is a 500 on a visitor's typo.
        raise NeoDBError("That does not look like a server address.") from exc

    netloc = f"{host}:{port}" if port else host
    return f"{parsed.scheme}://{netloc}"


def assert_public_host(instance: str, *, allow_private: bool = False) -> None:
    """
    Refuses instances that resolve to addresses we have no business reaching.

    This service takes a hostname from an untrusted visitor and then makes
    server-side requests to it, which is the classic shape of an SSRF hole:
    without this, anyone could point it at a cloud metadata endpoint or something
    else on the internal network and use the portal as a proxy.

    Resolution here and connection later are not atomic, so a determined attacker
    could still rebind DNS in between. Blocking the obvious cases is worthwhile
    even though it is not airtight; run the portal somewhere with no interesting
    internal network if that matters to you.
    """
    if allow_private:
        return

    host = urlparse(instance).hostname
    if not host:
        raise NeoDBError("That does not look like a server address.")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise NeoDBError(f"Could not find a server at {host}.") from exc

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise NeoDBError(f"{host} does not resolve to a public address.")


class NeoDBClient:
    """
    Talks to NeoDB instances on behalf of the portal.

    Registered app credentials are cached in memory per instance and app name --
    both, because two devices pairing against the same instance under different
    names must not share a registration, or the second one's owner would be asked
    to approve the first one's name. Losing the cache on restart costs one extra
    registration call, which is a fair price for keeping the promise that this
    service stores nothing.
    """

    def __init__(
        self,
        redirect_uri: str,
        *,
        website: str | None = None,
        timeout: float = 10.0,
        allow_private_hosts: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.redirect_uri = redirect_uri
        self.website = website
        self.timeout = timeout
        self.allow_private_hosts = allow_private_hosts
        self._transport = transport
        self._apps: dict[tuple[str, str], AppCredentials] = {}
        self._lock = threading.Lock()

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            transport=self._transport,
            headers={"Accept": "application/json"},
        )

    def check_instance(self, value: str) -> str:
        instance = normalize_instance(value, allow_insecure=self.allow_private_hosts)
        assert_public_host(instance, allow_private=self.allow_private_hosts)
        return instance

    async def app_credentials(self, instance: str, client_name: str) -> AppCredentials:
        name = clean_client_name(client_name)
        key = (instance, name)
        with self._lock:
            cached = self._apps.get(key)
        if cached is not None:
            return cached

        form = {
            "client_name": name,
            "redirect_uris": self.redirect_uri,
            # Mastodon defaults to read-only when scopes are omitted, which would
            # leave the paired device unable to mark anything.
            "scopes": OAUTH_SCOPES,
        }
        if self.website:
            form["website"] = self.website

        async with self._client() as client:
            try:
                response = await client.post(f"{instance}/api/v1/apps", data=form)
            except httpx.HTTPError as exc:
                raise NeoDBError(f"Could not reach {_host(instance)}.") from exc

        if response.status_code >= 400:
            raise NeoDBError(
                f"{_host(instance)} refused to register this app "
                f"(HTTP {response.status_code}). Is it a NeoDB server?"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise NeoDBError(
                f"{_host(instance)} did not answer with JSON. Is it a NeoDB server?"
            ) from exc

        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret")
        if not client_id or not client_secret:
            raise NeoDBError(f"{_host(instance)} did not return app credentials.")

        credentials = AppCredentials(client_id=client_id, client_secret=client_secret)
        with self._lock:
            self._apps[key] = credentials
        return credentials

    def authorize_url(
        self, instance: str, credentials: AppCredentials, state: str
    ) -> str:
        return (
            f"{instance}/oauth/authorize"
            f"?response_type=code"
            f"&client_id={quote(credentials.client_id, safe='')}"
            f"&redirect_uri={quote(self.redirect_uri, safe='')}"
            f"&scope={quote(OAUTH_SCOPES, safe='')}"
            f"&state={quote(state, safe='')}"
        )

    async def exchange_code(
        self, instance: str, credentials: AppCredentials, code: str
    ) -> TokenGrant:
        async with self._client() as client:
            try:
                response = await client.post(
                    f"{instance}/oauth/token",
                    data={
                        "client_id": credentials.client_id,
                        "client_secret": credentials.client_secret,
                        "code": code,
                        "redirect_uri": self.redirect_uri,
                        "grant_type": "authorization_code",
                    },
                )
            except httpx.HTTPError as exc:
                raise NeoDBError(f"Could not reach {_host(instance)}.") from exc

        if response.status_code >= 400:
            raise NeoDBError(
                "That sign-in could not be completed. Authorization codes expire "
                "quickly, so please start again."
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise NeoDBError("The server's reply could not be read.") from exc

        token = payload.get("access_token")
        if not token:
            raise NeoDBError("The server did not return an access token.")

        expires_in = payload.get("expires_in")
        try:
            expires_in = int(expires_in) if expires_in is not None else None
        except TypeError, ValueError:
            expires_in = None

        return TokenGrant(
            access_token=token,
            refresh_token=payload.get("refresh_token") or None,
            token_type=payload.get("token_type") or None,
            scope=payload.get("scope") or None,
            expires_in=expires_in,
        )

    async def whoami(self, instance: str, access_token: str) -> dict:
        async with self._client() as client:
            try:
                response = await client.get(
                    f"{instance}/api/me",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            except httpx.HTTPError as exc:
                raise NeoDBError(f"Could not reach {_host(instance)}.") from exc
        if response.status_code >= 400:
            raise NeoDBError("The new token was rejected by the server.")
        try:
            return response.json()
        except ValueError as exc:
            raise NeoDBError("The server's reply could not be read.") from exc


def _host(instance: str) -> str:
    return urlparse(instance).netloc or instance


# -- the published instance list ---------------------------------------------

#: Refresh attempts are floored this far apart. Pairings arrive in bursts (a
#: device retries, a household sets up three readers) while the published list
#: changes on the order of months, so the trigger is deliberately cheap to hit
#: and the floor is what keeps it from mattering.
REFRESH_INTERVAL = 60.0


def parse_servers(payload: dict) -> list[Instance]:
    """
    Turns a `servers.json` document into picker entries.

    Takes the document at its word: it is published by the same people who run
    this service, so it is not a trust boundary. A document that does not match
    the documented shape raises, and the caller treats that exactly like an
    unreachable feed -- logged, previous list kept.
    """
    entries: list[Instance] = []
    for server in payload["servers"]:
        # "flagship" + ["zh", "en"] reads as "Flagship · zh, en". The published
        # descriptions are whole sentences, too long for a radio button.
        notes = [label.capitalize() for label in server.get("label") or []]
        languages = ", ".join(server.get("language") or [])
        if languages:
            notes.append(languages)
        entries.append(
            {
                "host": server["host"],
                # An instance publishing no name of its own is simply NeoDB.
                "name": server.get("name") or "NeoDB",
                "note": " · ".join(notes),
            }
        )

    return entries


class InstanceDirectory:
    """
    The instance picker's contents, refreshed in the background.

    Held here rather than fetched per page because the list is the same for
    every visitor and changes on the order of months. Refreshes are triggered by
    pairing codes being generated -- traffic the service is already handling --
    so an idle process makes no outbound requests at all, matching how
    `SessionStore` sweeps on access instead of on a timer.

    A refresh never blocks the request that triggered it and never fails it: the
    device asking for a code does not care about the picker, and the visitor who
    will care arrives a QR scan later.
    """

    def __init__(
        self,
        url: str,
        *,
        interval: float = REFRESH_INTERVAL,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        seed: list[Instance] | None = None,
    ) -> None:
        self.url = url
        self.interval = interval
        self.timeout = timeout
        self._transport = transport
        self._lock = threading.Lock()
        self._instances = [dict(entry) for entry in (seed or KNOWN_INSTANCES)]
        self._last_attempt: float | None = None
        self._task: asyncio.Task[list[Instance]] | None = None

    def current(self) -> list[Instance]:
        """A snapshot, so a refresh landing mid-render cannot tear the list."""
        with self._lock:
            return list(self._instances)

    def schedule_refresh(self) -> bool:
        """
        Starts a refresh if one is due, and returns whether it did.

        Never raises and never awaits: the caller is serving an unrelated
        request. The attempt is timestamped before the task is created, so a
        burst of simultaneous callers produces one fetch rather than one each,
        and a feed that is failing is retried at the same slow rate as one that
        is working instead of on every single code.
        """
        if not self.url:
            return False

        now = time.monotonic()
        with self._lock:
            if self._task is not None and not self._task.done():
                return False
            if (
                self._last_attempt is not None
                and now - self._last_attempt < self.interval
            ):
                return False
            self._last_attempt = now

        try:
            task = asyncio.get_running_loop().create_task(self.refresh())
        except RuntimeError:  # pragma: no cover - no loop, e.g. a sync caller
            return False

        with self._lock:
            self._task = task
        # Nothing ever awaits this task, so nothing would ever retrieve its
        # exception; without this it surfaces as an "exception was never
        # retrieved" warning from the garbage collector, long after the fact.
        task.add_done_callback(self._refresh_finished)
        return True

    def _refresh_finished(self, task: asyncio.Task[list[Instance]]) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            logger.warning("could not refresh the instance list", exc_info=error)

    async def refresh(self) -> list[Instance]:
        """
        Fetches and installs the published list, returning what is now current.

        Raises on transport and decode failures so a caller that awaits this
        directly -- a test, or a future warm-up on startup -- sees why. The
        fire-and-forget path logs instead, via the done callback.
        """
        async with httpx.AsyncClient(
            timeout=self.timeout,
            transport=self._transport,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        ) as client:
            response = await client.get(self.url)
        response.raise_for_status()
        entries = parse_servers(response.json())

        if not entries:
            # A reachable feed that parses to nothing is a broken feed. Keeping
            # the previous list beats offering the visitor an empty picker.
            logger.warning("instance list at %s yielded no usable entries", self.url)
            return self.current()

        with self._lock:
            self._instances = entries
        logger.info("instance list refreshed: %d entries", len(entries))
        return list(entries)
