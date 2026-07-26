"""
Short-lived pairing sessions, held in memory only.

A session is the handshake between a device that cannot comfortably run a login
flow (an e-reader) and a phone that can. The device opens a session, shows its
join URL as a QR code, and later collects whatever the phone obtained.

Nothing here is written to disk. A restart drops every pending session, which is
the intended trade: these objects carry access tokens, and the longest any of
them is meant to live is a few minutes.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

# No 0/O/1/l/I: the code ends up in a URL that someone may have to read off one
# screen and type into another when the camera will not cooperate.
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"

#: Codes sit at the root of the URL rather than under a prefix, which buys two
#: characters of entropy at no cost to how dense the QR code ends up.
#: 30 ** 10 is about 5.9e14 -- and a code is useless on its own anyway, since
#: collecting the credentials needs the fetch token.
CODE_LENGTH = 10

#: Long enough that guessing is hopeless. Never shown to the user, never in a URL.
FETCH_TOKEN_BYTES = 32


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


class SessionError(Exception):
    """Raised when a session cannot be created or found."""


@dataclass
class Session:
    """One pending or completed device login."""

    code: str
    fetch_token: str
    created_at: float
    expires_at: float

    #: What the device calls itself. Registered with the instance and shown on
    #: its consent screen, so it belongs to the session rather than the service:
    #: one portal pairs many kinds of device.
    client_name: str

    #: Set when the phone picks an instance and we send it off to authorize.
    instance: str | None = None
    state: str | None = None

    #: Set once the authorization code has been exchanged. The app credentials
    #: travel with the token because the device needs them to refresh it later,
    #: and this service deliberately keeps nothing to look them up with.
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str | None = None
    scope: str | None = None
    token_expires_in: int | None = None
    client_id: str | None = None
    client_secret: str | None = None
    username: str | None = None
    display_name: str | None = None

    #: Guards against a second phone hijacking a session already in flight.
    started_at: float | None = None

    @property
    def ready(self) -> bool:
        return self.access_token is not None

    def expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.monotonic()) >= self.expires_at

    def seconds_left(self, now: float | None = None) -> int:
        now = now if now is not None else time.monotonic()
        return max(0, int(self.expires_at - now))


class SessionStore:
    """
    A thread-safe dictionary of sessions with a time-to-live.

    Expired entries are swept on every access rather than by a background task,
    so an idle process does no work and holds nothing.
    """

    def __init__(self, ttl_seconds: int = 900, max_sessions: int = 10_000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._by_state: dict[str, str] = {}

    # -- internals ---------------------------------------------------------

    def _purge(self, now: float) -> None:
        """Caller must hold the lock."""
        stale = [code for code, s in self._sessions.items() if s.expired(now)]
        for code in stale:
            session = self._sessions.pop(code, None)
            if session and session.state:
                self._by_state.pop(session.state, None)

    def _drop(self, session: Session) -> None:
        """Caller must hold the lock."""
        self._sessions.pop(session.code, None)
        if session.state:
            self._by_state.pop(session.state, None)

    # -- API ---------------------------------------------------------------

    def create(self, client_name: str) -> Session:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            if len(self._sessions) >= self.max_sessions:
                raise SessionError("too many pending sessions")

            for _ in range(10):
                code = new_code()
                if code not in self._sessions:
                    break
            else:  # pragma: no cover - astronomically unlikely
                raise SessionError("could not allocate a session code")

            session = Session(
                code=code,
                fetch_token=secrets.token_urlsafe(FETCH_TOKEN_BYTES),
                created_at=now,
                expires_at=now + self.ttl_seconds,
                client_name=client_name,
            )
            self._sessions[code] = session
            return session

    def get(self, code: str) -> Session | None:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            return self._sessions.get(code)

    def begin_authorization(self, code: str, instance: str) -> Session:
        """Records the chosen instance and issues a fresh OAuth `state`."""
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            session = self._sessions.get(code)
            if session is None:
                raise SessionError("unknown or expired session")
            if session.ready:
                raise SessionError("this session has already been completed")

            if session.state:
                # Restarting: the previous state must stop being accepted.
                self._by_state.pop(session.state, None)

            session.instance = instance
            session.state = secrets.token_urlsafe(24)
            session.started_at = now
            self._by_state[session.state] = code
            return session

    def find_by_state(self, state: str) -> Session | None:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            code = self._by_state.get(state)
            return self._sessions.get(code) if code else None

    def complete(
        self,
        state: str,
        access_token: str,
        *,
        refresh_token: str | None = None,
        token_type: str | None = None,
        scope: str | None = None,
        token_expires_in: int | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        display_name: str | None = None,
    ) -> Session:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            code = self._by_state.get(state)
            session = self._sessions.get(code) if code else None
            if session is None:
                raise SessionError("unknown or expired session")

            session.access_token = access_token
            session.refresh_token = refresh_token
            session.token_type = token_type
            session.scope = scope
            session.token_expires_in = token_expires_in
            session.client_id = client_id
            session.client_secret = client_secret
            session.username = username
            session.display_name = display_name
            # The state has served its purpose; retiring it stops a replayed
            # callback from overwriting a completed session.
            self._by_state.pop(state, None)
            session.state = None
            return session

    def claim(self, code: str, fetch_token: str) -> Session | None:
        """
        Hands the credentials to the device that opened the session, once.

        Returns None when the session is unknown, expired, or the token does not
        match. A pending session is returned without being removed so the device
        can ask again; a completed one is removed as it is handed over.
        """
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            session = self._sessions.get(code)
            if session is None:
                return None
            if not secrets.compare_digest(session.fetch_token, fetch_token):
                return None
            if session.ready:
                self._drop(session)
            return session

    def discard(self, code: str, fetch_token: str) -> bool:
        with self._lock:
            session = self._sessions.get(code)
            if session is None:
                return False
            if not secrets.compare_digest(session.fetch_token, fetch_token):
                return False
            self._drop(session)
            return True

    def __len__(self) -> int:
        with self._lock:
            self._purge(time.monotonic())
            return len(self._sessions)
