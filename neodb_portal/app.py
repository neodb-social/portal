"""
HTTP surface of the portal.

Two audiences, deliberately kept apart:

* `/api/...` and `/svc/...` are the machinery: the device opens a session and
  later collects the result, authenticating with a fetch token that never appears
  in a URL or on screen, and instances hand visitors back through
  `/svc/callback`.
* `/{code}` is the phone. It picks an instance, signs in there, and returns. It
  never sees the fetch token, so someone who shoulder-surfs or guesses a join
  code still cannot lift the credentials afterwards.

Pairing codes live at the root of the path space, which keeps the join URL short
enough to make an easy QR code. Everything the service owns is therefore under a
reserved prefix, so no code can ever shadow a real route.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi import APIRouter, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from .config import Settings
from .metrics import Metrics
from .neodb import InstanceDirectory, NeoDBClient, NeoDBError, clean_client_name
from .sessions import CODE_ALPHABET, CODE_LENGTH, SessionError, SessionStore

#: Paths the service owns. A pairing code can never be one of these, because the
#: code alphabet has no letters outside its own set -- but reserving them keeps
#: the intent explicit for anyone adding a route later.
RESERVED_PREFIXES = ("api", "svc", "healthz", "robots.txt")

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

#: Every URL here is either a single-use credential hand-off or a machine
#: endpoint. None of it should be indexed, and a crawler walking pairing codes
#: would only burn them.
ROBOTS_TXT = b"User-agent: *\nDisallow: /\n"


class RateLimiter:
    """A crude per-client budget, enough to keep the session store bounded."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(hits) >= self.per_minute:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 10_000:  # keep the table from growing forever
                for stale in [
                    k for k, v in self._hits.items() if not v or max(v) <= cutoff
                ]:
                    self._hits.pop(stale, None)
            return True


def looks_like_code(value: str) -> bool:
    """Cheap shape check, so a stray URL 404s instead of claiming to have expired."""
    return (
        len(value) == CODE_LENGTH
        and value not in RESERVED_PREFIXES
        and all(character in CODE_ALPHABET for character in value)
    )


def create_app(
    settings: Settings | None = None,
    *,
    client: NeoDBClient | None = None,
    metrics: Metrics | None = None,
    instances: InstanceDirectory | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    sessions = SessionStore(
        ttl_seconds=settings.session_ttl, max_sessions=settings.max_sessions
    )
    neodb = client or NeoDBClient(
        redirect_uri=settings.redirect_uri,
        website=settings.website,
        allow_private_hosts=settings.allow_private_hosts,
    )
    directory = instances or InstanceDirectory(
        settings.servers_url, interval=settings.servers_refresh_interval
    )
    limiter = RateLimiter(settings.create_rate_per_minute)
    stats = metrics or Metrics(
        settings.sentry_dsn,
        environment=settings.sentry_environment,
        traces_sample_rate=settings.sentry_traces_sample_rate,
    )

    app = FastAPI(
        title="NeoDB Portal",
        description="Pairs a device with a NeoDB account by scanning a QR code.",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.sessions = sessions
    app.state.neodb = neodb
    app.state.metrics = stats
    app.state.instances = directory

    api = APIRouter(prefix="/api")

    def client_key(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not value:
            return None
        return value.strip()

    # -- device API --------------------------------------------------------

    @api.post("/session", status_code=201)
    async def open_session(request: Request, client_name: str = Form(...)):
        """
        Opens a pairing session. The device renders `join_url` as a QR code.

        `client_name` is what the device calls itself. It is registered with
        whichever instance the phone picks and shown on that instance's consent
        screen, so it is the device's to choose, not this service's -- one portal
        pairs many kinds of device, and "NeoDB Portal" tells nobody anything.
        """
        if not limiter.allow(client_key(request)):
            raise HTTPException(status_code=429, detail="Too many sessions; slow down.")
        try:
            name = clean_client_name(client_name)
        except NeoDBError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            session = sessions.create(client_name=name)
        except SessionError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        # A code has just been generated, so a visitor is about to be shown the
        # instance picker -- the one moment when a stale list would be visible,
        # and the last moment it can still be refreshed in time. Fire-and-forget
        # and rate limited internally: this request is the device's, not the
        # picker's, and must not wait on or fail with an outbound fetch.
        directory.schedule_refresh()

        stats.request()
        return {
            "code": session.code,
            "fetch_token": session.fetch_token,
            "join_url": settings.join_url(session.code),
            "expires_in": session.seconds_left(),
        }

    @api.get("/session/{code}")
    async def poll_session(code: str, authorization: str | None = Header(default=None)):
        """
        Reports progress, and hands over the credentials exactly once.

        A pending session answers 202 so the device can simply ask again; a
        completed one answers 200 and is dropped in the same breath.
        """
        token = bearer(authorization)
        if not token:
            raise HTTPException(status_code=401, detail="Missing fetch token.")

        session = sessions.claim(code, token)
        if session is None:
            # Unknown, expired, or wrong token: all the same to a caller, so
            # that a guessed code learns nothing from the distinction.
            raise HTTPException(status_code=404, detail="No such session.")

        if not session.ready:
            return JSONResponse(
                status_code=202,
                content={
                    "status": "pending",
                    "instance": session.instance,
                    "expires_in": session.seconds_left(),
                },
            )

        stats.link(session.instance)
        # Everything the device needs to keep talking to the instance on its
        # own, including the app registration -- this is the only time it is
        # offered, and the portal has already forgotten it by the next line.
        return {
            "status": "ready",
            "instance": session.instance,
            "client_name": session.client_name,
            "client_id": session.client_id,
            "client_secret": session.client_secret,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "token_type": session.token_type,
            "scope": session.scope,
            "token_expires_in": session.token_expires_in,
            "username": session.username,
            "display_name": session.display_name,
        }

    @api.delete("/session/{code}", status_code=204)
    async def close_session(
        code: str, authorization: str | None = Header(default=None)
    ):
        token = bearer(authorization)
        if not token or not sessions.discard(code, token):
            raise HTTPException(status_code=404, detail="No such session.")
        return None

    app.include_router(api)

    # -- phone-facing pages ------------------------------------------------

    def page(request: Request, name: str, /, status_code: int = 200, **context):
        return TEMPLATES.TemplateResponse(
            request=request, name=name, status_code=status_code, context=context
        )

    def problem(request: Request, message: str, status_code: int = 400):
        return page(request, "error.html", status_code=status_code, message=message)

    @app.get("/svc/callback", response_class=HTMLResponse)
    async def callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ):
        if error:
            return problem(request, f"The server reported: {error}")
        if not code or not state:
            return problem(request, "That sign-in did not come back with a code.")

        session = sessions.find_by_state(state)
        if session is None or not session.instance:
            return problem(
                request,
                "This sign-in took too long and the link expired. "
                "Start again on your device.",
                status_code=404,
            )

        try:
            credentials = await neodb.app_credentials(
                session.instance, session.client_name
            )
            grant = await neodb.exchange_code(session.instance, credentials, code)
        except NeoDBError as exc:
            return problem(request, str(exc))

        username = display_name = None
        try:
            me = await neodb.whoami(session.instance, grant.access_token)
            username = me.get("username")
            display_name = me.get("display_name")
        except NeoDBError:
            # Not fatal: the device verifies the token itself before storing it.
            pass

        try:
            sessions.complete(
                state,
                grant.access_token,
                refresh_token=grant.refresh_token,
                token_type=grant.token_type,
                scope=grant.scope,
                token_expires_in=grant.expires_in,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                username=username,
                display_name=display_name,
            )
        except SessionError as exc:
            return problem(request, str(exc))

        return page(request, "done.html", instance=session.instance, username=username)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return page(request, "index.html")

    @app.get("/robots.txt", include_in_schema=False)
    async def robots():
        return Response(
            ROBOTS_TXT,
            media_type="text/plain",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "pending_sessions": len(sessions)}

    # -- pairing codes, last ----------------------------------------------
    #
    # `/{code}` matches any single path segment, so it has to be registered
    # after every real route or it would swallow them: Starlette takes the first
    # match in registration order, and /healthz is one segment too.

    @app.get("/{code}", response_class=HTMLResponse)
    async def join(request: Request, code: str):
        if not looks_like_code(code):
            raise HTTPException(status_code=404, detail="Not found.")
        session = sessions.get(code)
        if session is None:
            return problem(
                request,
                "This sign-in link has expired or was already used. "
                "Start again on your device to get a fresh one.",
                status_code=404,
            )
        if session.ready:
            return page(
                request,
                "done.html",
                instance=session.instance,
                username=session.username,
            )
        return page(
            request,
            "join.html",
            code=code,
            instances=directory.current(),
            minutes_left=max(1, session.seconds_left() // 60),
        )

    @app.post("/{code}", response_class=HTMLResponse)
    async def start(
        request: Request,
        code: str,
        instance: str = Form(...),
        other: str = Form(default=""),
    ):
        if not looks_like_code(code):
            raise HTTPException(status_code=404, detail="Not found.")
        session = sessions.get(code)
        if session is None:
            return problem(
                request,
                "This sign-in link has expired. Start again on your device.",
                status_code=404,
            )

        # The last radio option stands for "something not on the list".
        if instance == "__other__":
            instance = other

        try:
            target = neodb.check_instance(instance)
            credentials = await neodb.app_credentials(target, session.client_name)
            started = sessions.begin_authorization(code, target)
        except (NeoDBError, SessionError) as exc:
            return page(
                request,
                "join.html",
                status_code=400,
                code=code,
                instances=directory.current(),
                minutes_left=max(1, session.seconds_left() // 60),
                error=str(exc),
                entered=instance,
            )

        stats.login(target)
        return RedirectResponse(
            neodb.authorize_url(target, credentials, started.state or ""),
            status_code=303,
        )

    return app


def get_app() -> FastAPI:
    """Factory for `uvicorn --factory neodb_portal.app:get_app`."""
    return create_app()
