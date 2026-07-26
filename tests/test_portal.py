"""
End-to-end exercise of the pairing flow against a stubbed NeoDB instance.

The NeoDB side is replaced with an httpx mock transport, so these tests cover
the portal's own behaviour -- session lifecycle, one-time hand-over, expiry,
and the checks that stop it being used as an open proxy.
"""

from __future__ import annotations

import asyncio
import time
from typing import TypedDict
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from neodb_portal.app import create_app, looks_like_code
from neodb_portal.config import Settings
from neodb_portal.metrics import LINK, LOGIN, REQUEST, Metrics, instance_host
from neodb_portal.neodb import (
    KNOWN_INSTANCES,
    InstanceDirectory,
    NeoDBClient,
    NeoDBError,
    normalize_instance,
    parse_servers,
)
from neodb_portal.sessions import SessionStore

INSTANCE = "https://neodb.social"


class Seen(TypedDict):
    """What the stubbed instance recorded about the calls it received."""

    apps: int
    app_form: str
    exchanges: list[dict[str, list[str]]]


def fake_neodb(*, token: str = "TOKEN", fail_exchange: bool = False):
    """A stand-in for a NeoDB instance's OAuth endpoints."""
    seen: Seen = {"apps": 0, "app_form": "", "exchanges": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/apps":
            seen["apps"] += 1
            seen["app_form"] = request.content.decode()
            return httpx.Response(
                200, json={"client_id": "CID", "client_secret": "SEC"}
            )
        if path == "/oauth/token":
            body = parse_qs(request.content.decode())
            seen["exchanges"].append(body)
            if fail_exchange:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": token,
                    "refresh_token": "REFRESH",
                    "token_type": "Bearer",
                    "scope": "read write",
                    "expires_in": 5184000,
                },
            )
        if path == "/api/me":
            if request.headers.get("Authorization") != f"Bearer {token}":
                return httpx.Response(401, json={"message": "bad token"})
            return httpx.Response(
                200, json={"username": "song", "display_name": "Song"}
            )
        return httpx.Response(404, json={"message": f"unhandled {path}"})

    return httpx.MockTransport(handler), seen


class RecordingMetrics(Metrics):
    """A Metrics that records instead of reporting, so counts can be asserted."""

    def __init__(self):  # noqa: D107 - deliberately skips Sentry setup
        self.enabled = True
        self._counter = None
        self.counts: list[tuple[str, dict]] = []

    def count(self, name, **attributes):
        self.counts.append((name, attributes))

    def names(self):
        return [name for name, _ in self.counts]


def build(*, instances=None, **kwargs):
    settings = Settings(base_url="https://p.neodb.net", **kwargs)
    transport, seen = fake_neodb()
    client = NeoDBClient(
        redirect_uri=settings.redirect_uri,
        transport=transport,
        # The stub answers for any host, so skip the DNS-based public check.
        allow_private_hosts=True,
    )
    stats = RecordingMetrics()
    # Default to a directory that fetches nothing, so tests of the pairing flow
    # never reach for the network on their own.
    app = create_app(
        settings,
        client=client,
        metrics=stats,
        instances=instances if instances is not None else InstanceDirectory(""),
    )
    test_client = TestClient(app)
    test_client.metrics = stats
    return test_client, seen


def open_session(client: TestClient, client_name: str = "Test Device"):
    """Opens a session the way a device does: naming itself as it goes."""
    return client.post("/api/session", data={"client_name": client_name})


# -- session lifecycle -------------------------------------------------------


def test_session_open_returns_join_url_and_secret():
    client, _ = build()
    response = open_session(client)
    assert response.status_code == 201
    body = response.json()

    assert len(body["code"]) == 10
    assert body["join_url"] == f"https://p.neodb.net/{body['code']}"
    assert body["expires_in"] > 0
    # The fetch token must not be derivable from anything the phone sees.
    assert body["fetch_token"] not in body["join_url"]
    assert len(body["fetch_token"]) >= 32


def test_full_pairing_flow():
    client, seen = build()
    opened = open_session(client).json()
    code, fetch_token = opened["code"], opened["fetch_token"]

    # the device polls before anything has happened
    pending = client.get(
        f"/api/session/{code}", headers={"Authorization": f"Bearer {fetch_token}"}
    )
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"

    # the phone opens the join page and picks an instance
    page = client.get(f"/{code}")
    assert page.status_code == 200
    assert "neodb.social" in page.text

    started = client.post(
        f"/{code}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    assert started.status_code == 303
    target = urlparse(started.headers["location"])
    query = parse_qs(target.query)
    assert target.netloc == "neodb.social"
    assert target.path == "/oauth/authorize"
    assert query["client_id"] == ["CID"]
    assert query["redirect_uri"] == ["https://p.neodb.net/svc/callback"]
    assert query["scope"] == ["read write"]
    state = query["state"][0]

    # registration must ask for write access, or the device can mark nothing
    assert (
        "scopes=read+write" in seen["app_form"]
        or "scopes=read%20write" in seen["app_form"]
    )

    # NeoDB sends the phone back
    done = client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})
    assert done.status_code == 200
    assert "Signed in" in done.text
    assert seen["exchanges"][0]["code"] == ["AUTHCODE"]
    assert seen["exchanges"][0]["redirect_uri"] == ["https://p.neodb.net/svc/callback"]

    # the device collects it
    ready = client.get(
        f"/api/session/{code}", headers={"Authorization": f"Bearer {fetch_token}"}
    )
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "instance": INSTANCE,
        "client_name": "Test Device",
        "client_id": "CID",
        "client_secret": "SEC",
        "access_token": "TOKEN",
        "refresh_token": "REFRESH",
        "token_type": "Bearer",
        "scope": "read write",
        "token_expires_in": 5184000,
        "username": "song",
        "display_name": "Song",
    }


def test_credentials_are_handed_over_only_once():
    client, _ = build()
    opened = open_session(client).json()
    code, fetch_token = opened["code"], opened["fetch_token"]
    auth = {"Authorization": f"Bearer {fetch_token}"}

    started = client.post(
        f"/{code}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})

    assert client.get(f"/api/session/{code}", headers=auth).status_code == 200
    # second attempt finds nothing: a leaked token cannot replay the pickup
    assert client.get(f"/api/session/{code}", headers=auth).status_code == 404


def test_join_code_alone_cannot_collect_the_token():
    client, _ = build()
    opened = open_session(client).json()
    code = opened["code"]

    started = client.post(
        f"/{code}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})

    # Knowing the code -- which is in the QR, and on screen -- is not enough.
    assert client.get(f"/api/session/{code}").status_code == 401
    assert (
        client.get(
            f"/api/session/{code}", headers={"Authorization": "Bearer wrong"}
        ).status_code
        == 404
    )

    # and the real token still works afterwards
    assert (
        client.get(
            f"/api/session/{code}",
            headers={"Authorization": f"Bearer {opened['fetch_token']}"},
        ).status_code
        == 200
    )


def test_unknown_session_and_wrong_token_are_indistinguishable():
    client, _ = build()
    opened = open_session(client).json()
    missing = client.get(
        "/api/session/aaaaaaaaaa", headers={"Authorization": "Bearer x"}
    )
    wrong = client.get(
        f"/api/session/{opened['code']}", headers={"Authorization": "Bearer x"}
    )
    assert missing.status_code == wrong.status_code == 404
    assert missing.json() == wrong.json()


def test_device_can_cancel_a_session():
    client, _ = build()
    opened = open_session(client).json()
    auth = {"Authorization": f"Bearer {opened['fetch_token']}"}
    assert (
        client.delete(f"/api/session/{opened['code']}", headers=auth).status_code == 204
    )
    assert client.get(f"/api/session/{opened['code']}", headers=auth).status_code == 404


def test_callback_rejects_an_unknown_state():
    client, _ = build()
    response = client.get("/svc/callback", params={"code": "X", "state": "made-up"})
    assert response.status_code == 404
    assert "expired" in response.text


def test_callback_state_cannot_be_replayed():
    client, _ = build()
    opened = open_session(client).json()
    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]

    assert (
        client.get("/svc/callback", params={"code": "A", "state": state}).status_code
        == 200
    )
    replay = client.get("/svc/callback", params={"code": "B", "state": state})
    assert replay.status_code == 404


def test_expired_session_is_gone():
    client, _ = build(session_ttl=1)
    opened = open_session(client).json()
    time.sleep(1.05)
    assert client.get(f"/{opened['code']}").status_code == 404
    assert (
        client.get(
            f"/api/session/{opened['code']}",
            headers={"Authorization": f"Bearer {opened['fetch_token']}"},
        ).status_code
        == 404
    )


def test_join_page_reports_a_failed_instance_without_losing_the_session():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(404, text="not neodb")
    )
    settings = Settings(base_url="https://p.neodb.net")
    client = TestClient(
        create_app(
            settings,
            client=NeoDBClient(
                redirect_uri=settings.redirect_uri,
                transport=transport,
                allow_private_hosts=True,
            ),
        )
    )
    opened = open_session(client).json()
    response = client.post(
        f"/{opened['code']}",
        data={"instance": "__other__", "other": "not-a-neodb.example"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "refused to register" in response.text
    # still usable, so the visitor can just pick a different instance
    assert client.get(f"/{opened['code']}").status_code == 200


def test_exchange_failure_is_explained():
    settings = Settings(base_url="https://p.neodb.net")
    transport, _ = fake_neodb(fail_exchange=True)
    client = TestClient(
        create_app(
            settings,
            client=NeoDBClient(
                redirect_uri=settings.redirect_uri,
                transport=transport,
                allow_private_hosts=True,
            ),
        )
    )
    opened = open_session(client).json()
    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    response = client.get("/svc/callback", params={"code": "STALE", "state": state})
    assert response.status_code == 400
    assert "expire" in response.text


def test_rate_limit_on_session_creation():
    client, _ = build(create_rate_per_minute=3)
    codes = [open_session(client) for _ in range(4)]
    assert [c.status_code for c in codes[:3]] == [201, 201, 201]
    assert codes[3].status_code == 429


def test_healthz_counts_pending_sessions():
    client, _ = build()
    assert client.get("/healthz").json()["pending_sessions"] == 0
    open_session(client)
    assert client.get("/healthz").json()["pending_sessions"] == 1


# -- client-supplied app name ------------------------------------------------


def test_device_names_itself_and_the_instance_is_told():
    client, seen = build()
    opened = open_session(client, "Kobo Clara").json()
    client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    assert "client_name=Kobo+Clara" in seen["app_form"]


def test_a_session_cannot_be_opened_anonymously():
    """There is no server-side default: an unnamed device is a bad request."""
    client, _ = build()
    assert client.post("/api/session").status_code == 422
    # An empty field is missing as far as form parsing is concerned.
    assert open_session(client, "").status_code == 422


@pytest.mark.parametrize(
    "name",
    [
        "   ",  # nothing but whitespace is no name at all
        "x" * 65,  # long enough to crowd out the real prompt
        "Reader\x00evil",  # control characters have no business on a consent screen
    ],
)
def test_unusable_client_names_are_refused(name):
    client, _ = build()
    assert open_session(client, name).status_code == 400


def test_client_name_is_not_accepted_from_the_query_string():
    """It travels in the body, so a query string is just a missing field."""
    client, _ = build()
    response = client.post("/api/session", params={"client_name": "Kobo Clara"})
    assert response.status_code == 422


def test_two_devices_do_not_share_an_app_registration():
    """
    Each name must get its own registration with the instance.

    Reusing one would show the second device's owner the first device's name on
    the consent screen -- the one thing the name is there to get right.
    """
    client, seen = build()
    for name in ("Kobo Clara", "Kindle"):
        opened = open_session(client, name).json()
        client.post(
            f"/{opened['code']}",
            data={"instance": "neodb.social"},
            follow_redirects=False,
        )
    assert seen["apps"] == 2

    # ...while a repeat of a name already registered reuses what we have.
    opened = open_session(client, "Kindle").json()
    client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    assert seen["apps"] == 2


# -- what the device gets back -----------------------------------------------


def test_app_credentials_travel_with_the_token():
    client, _ = build()
    opened = open_session(client, "Kobo Clara").json()
    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})

    ready = client.get(
        f"/api/session/{opened['code']}",
        headers={"Authorization": f"Bearer {opened['fetch_token']}"},
    ).json()
    # Enough to refresh the token without ever coming back here.
    assert ready["client_name"] == "Kobo Clara"
    assert ready["client_id"] == "CID"
    assert ready["client_secret"] == "SEC"
    assert ready["refresh_token"] == "REFRESH"
    assert ready["token_type"] == "Bearer"
    assert ready["scope"] == "read write"
    assert ready["token_expires_in"] == 5184000


def test_an_uncollected_grant_is_forgotten_when_the_session_expires():
    client, _ = build(session_ttl=1)
    opened = open_session(client).json()
    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    assert (
        client.get(
            "/svc/callback", params={"code": "AUTHCODE", "state": state}
        ).status_code
        == 200
    )

    time.sleep(1.05)
    # The device never came back for it, so the secrets go with the session.
    assert (
        client.get(
            f"/api/session/{opened['code']}",
            headers={"Authorization": f"Bearer {opened['fetch_token']}"},
        ).status_code
        == 404
    )
    assert client.get("/healthz").json()["pending_sessions"] == 0


# -- instance validation -----------------------------------------------------


@pytest.mark.parametrize(
    "given,expected",
    [
        ("neodb.social", "https://neodb.social"),
        ("https://neodb.social", "https://neodb.social"),
        ("https://neodb.social/", "https://neodb.social"),
        ("  https://neodb.social/users/me/  ", "https://neodb.social"),
        ("NeoDB.Social", "https://neodb.social"),
    ],
)
def test_instance_normalization(given, expected):
    assert normalize_instance(given) == expected


@pytest.mark.parametrize(
    "given", ["", "   ", "neodb", "ftp://neodb.social", "http://neodb.social"]
)
def test_instance_normalization_rejects(given):
    with pytest.raises(NeoDBError):
        normalize_instance(given)


@pytest.mark.parametrize(
    "host",
    [
        "http://localhost:8000",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://10.0.0.5",
    ],
)
def test_private_addresses_are_refused(host):
    """The portal fetches URLs a stranger supplies, so it must not reach inward."""
    client = NeoDBClient(redirect_uri="https://p.neodb.net/svc/callback")
    with pytest.raises(NeoDBError):
        client.check_instance(host)


# -- store behaviour ---------------------------------------------------------


def test_store_purges_expired_entries():
    store = SessionStore(ttl_seconds=1)
    store.create("Test Device")
    assert len(store) == 1
    time.sleep(1.05)
    assert len(store) == 0


def test_store_refuses_to_grow_without_bound():
    store = SessionStore(ttl_seconds=60, max_sessions=2)
    store.create("Test Device")
    store.create("Test Device")
    with pytest.raises(Exception):
        store.create("Test Device")


def test_restarting_authorization_retires_the_old_state():
    store = SessionStore(ttl_seconds=60)
    session = store.create("Test Device")
    first = store.begin_authorization(session.code, INSTANCE).state
    second = store.begin_authorization(session.code, INSTANCE).state
    assert first and second and first != second
    assert store.find_by_state(first) is None
    assert store.find_by_state(second) is not None


# -- routing shape -----------------------------------------------------------


def test_join_url_has_no_prefix_and_stays_short():
    client, _ = build()
    body = open_session(client).json()
    # 10 characters at the root is the same total length as 8 under /j/, so the
    # QR code is no denser for the extra entropy.
    assert body["join_url"] == f"https://p.neodb.net/{body['code']}"
    assert len(body["join_url"]) == len("https://p.neodb.net/") + 10


def test_service_routes_are_not_shadowed_by_the_code_route():
    client, _ = build()
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200
    # /svc/callback belongs to the service, and no code can look like it
    assert client.get("/svc/callback").status_code == 400


@pytest.mark.parametrize(
    "path",
    [
        "/favicon.ico",
        "/svc/icon.png",
        "/wp-login.php",
        "/short",
        "/UPPERCASE1",
        "/abcdefghi0",
        "/j/abcdefghjk",
    ],
)
def test_stray_paths_are_plain_404s(path):
    """A crawler should not be told a session expired; it never had one."""
    client, _ = build()
    assert client.get(path).status_code == 404


# -- static assets -----------------------------------------------------------


def test_robots_disallows_everything():
    client, _ = build()
    response = client.get("/robots.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == "User-agent: *\nDisallow: /\n"


def test_assets_are_cacheable():
    client, _ = build()
    assert "max-age" in client.get("/robots.txt").headers["cache-control"]


def test_robots_is_not_swallowed_by_the_code_route():
    """It sits at the root, where /{code} could have caught it."""
    client, _ = build()
    assert client.get("/robots.txt").status_code == 200


def test_looks_like_code_rejects_reserved_and_malformed():
    assert not looks_like_code("healthz")
    assert not looks_like_code("api")
    assert not looks_like_code("short")
    assert not looks_like_code("abcdefghi0")  # 0 is not in the alphabet
    assert looks_like_code("abcdefghjk")


# -- metrics -----------------------------------------------------------------


def test_the_three_counters_fire_in_order():
    client, _ = build()
    stats = client.metrics

    opened = open_session(client).json()
    assert stats.names() == [REQUEST]

    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    assert stats.names() == [REQUEST, LOGIN]
    assert stats.counts[1][1] == {"instance": "neodb.social"}

    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})
    # the callback itself is not an event; linking is what counts
    assert stats.names() == [REQUEST, LOGIN]

    client.get(
        f"/api/session/{opened['code']}",
        headers={"Authorization": f"Bearer {opened['fetch_token']}"},
    )
    assert stats.names() == [REQUEST, LOGIN, LINK]
    assert stats.counts[2][1] == {"instance": "neodb.social"}


def test_a_pending_poll_is_not_counted_as_a_link():
    client, _ = build()
    opened = open_session(client).json()
    client.get(
        f"/api/session/{opened['code']}",
        headers={"Authorization": f"Bearer {opened['fetch_token']}"},
    )
    assert client.metrics.names() == [REQUEST]


def test_metrics_carry_no_identifiers():
    """Only the instance host is ever attached -- never a code, token or user."""
    client, _ = build()
    opened = open_session(client).json()
    started = client.post(
        f"/{opened['code']}", data={"instance": "neodb.social"}, follow_redirects=False
    )
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    client.get("/svc/callback", params={"code": "AUTHCODE", "state": state})
    client.get(
        f"/api/session/{opened['code']}",
        headers={"Authorization": f"Bearer {opened['fetch_token']}"},
    )

    for _name, attributes in client.metrics.counts:
        assert set(attributes) <= {"instance"}
        for value in attributes.values():
            assert opened["code"] not in value
            assert opened["fetch_token"] not in value
            assert "song" not in value


def test_metrics_are_a_no_op_without_a_dsn():
    stats = Metrics(None)
    assert stats.enabled is False
    stats.request()
    stats.login("https://neodb.social")
    stats.link(None)  # must not raise


def test_instance_host_never_leaks_a_path():
    assert instance_host("https://neodb.social/users/song/") == "neodb.social"
    assert instance_host(None) == "unknown"
    assert instance_host("") == "unknown"


def test_sentry_is_wired_up_when_a_dsn_is_given(monkeypatch):
    """With a DSN, counts must reach sentry_sdk.metrics.count with our attributes."""
    recorded = []

    import sentry_sdk
    from sentry_sdk import metrics as sentry_metrics

    monkeypatch.setattr(sentry_sdk, "init", lambda **kwargs: recorded.append(kwargs))
    monkeypatch.setattr(
        sentry_metrics,
        "count",
        lambda name, value, unit=None, attributes=None: recorded.append(
            (name, value, attributes)
        ),
    )

    stats = Metrics("https://public@example.invalid/1", environment="test")
    assert stats.enabled

    init_kwargs = recorded[0]
    # A service that handles access tokens must not let the SDK attach request
    # bodies or user identifiers to anything it sends.
    assert init_kwargs["send_default_pii"] is False
    assert init_kwargs["max_request_body_size"] == "never"
    assert init_kwargs["environment"] == "test"

    stats.request()
    stats.login("https://neodb.social/users/song/")
    stats.link("https://neodb.social")

    assert recorded[1] == (REQUEST, 1, None)
    assert recorded[2] == (LOGIN, 1, {"instance": "neodb.social"})
    assert recorded[3] == (LINK, 1, {"instance": "neodb.social"})


def test_a_broken_metrics_backend_cannot_break_a_sign_in(monkeypatch):
    stats = Metrics(None)
    stats.enabled = True

    def explode(*args, **kwargs):
        raise RuntimeError("sentry is down")

    stats._counter = explode
    stats.request()  # must not raise
    stats.link("https://neodb.social")


# -- the published instance list ---------------------------------------------
#
# The picker's contents are fetched from NeoDB's servers.json rather than pinned
# in the source. These cover the three things that can go wrong: the document is
# hostile, the feed is down, or the refresh runs so often it becomes a stampede.

SERVERS_DOC = {
    "version": "1.0",
    "servers": [
        # The flagship publishes no name of its own.
        {
            "host": "neodb.social",
            "description": "Flagship instance, managed by NeoDB developers.",
            "label": ["flagship"],
            "language": ["zh", "en"],
        },
        {
            "host": "eggplant.place",
            "name": "NeoDB experimental",
            "label": ["beta"],
            "language": ["en"],
        },
        {"host": "minreol.dk", "name": "Minreol", "language": ["da"]},
    ],
}


def servers_transport(doc=SERVERS_DOC, *, status: int = 200, calls: list | None = None):
    """Stands in for neodb.net/servers.json, counting the fetches it serves."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        if status != 200:
            return httpx.Response(status, text="unavailable")
        return httpx.Response(200, json=doc)

    return httpx.MockTransport(handler)


def directory(doc=SERVERS_DOC, *, status=200, calls=None, interval=60.0, seed=None):
    return InstanceDirectory(
        "https://neodb.net/servers.json",
        interval=interval,
        transport=servers_transport(doc, status=status, calls=calls),
        seed=seed,
    )


async def settle(directory_: InstanceDirectory) -> None:
    """
    Waits for the in-flight refresh, if there is one.

    Nothing in the service ever awaits a scheduled refresh -- that is the point
    of it -- so a test has to reach for the task itself to be deterministic
    rather than sleeping and hoping.
    """
    if directory_._task is not None:
        await asyncio.gather(directory_._task, return_exceptions=True)


def test_parse_servers_maps_the_published_shape():
    assert parse_servers(SERVERS_DOC) == [
        # No published name, so it is simply NeoDB; label and languages become
        # the one line that fits under a radio button.
        {"host": "neodb.social", "name": "NeoDB", "note": "Flagship · zh, en"},
        {"host": "eggplant.place", "name": "NeoDB experimental", "note": "Beta · en"},
        {"host": "minreol.dk", "name": "Minreol", "note": "da"},
    ]


async def test_refresh_installs_the_published_list():
    calls: list[str] = []
    directory_ = directory(calls=calls)

    assert [entry["host"] for entry in directory_.current()] == [
        entry["host"] for entry in KNOWN_INSTANCES
    ]

    await directory_.refresh()

    assert calls == ["https://neodb.net/servers.json"]
    assert [entry["host"] for entry in directory_.current()] == [
        "neodb.social",
        "eggplant.place",
        "minreol.dk",
    ]


async def test_a_dead_feed_leaves_the_previous_list_alone():
    directory_ = directory(status=503)
    before = directory_.current()

    with pytest.raises(httpx.HTTPStatusError):
        await directory_.refresh()

    assert directory_.current() == before


async def test_an_empty_feed_leaves_the_previous_list_alone():
    # Reachable and valid, but empty -- a typo in a deploy of the list itself.
    # An empty picker is worse than a stale one, so the old list stands.
    directory_ = directory({"servers": []})
    before = directory_.current()

    await directory_.refresh()

    assert directory_.current() == before


async def test_refresh_is_floored_at_one_attempt_per_interval():
    calls: list[str] = []
    directory_ = directory(calls=calls, interval=60.0)

    assert directory_.schedule_refresh() is True
    # Same interval, so neither of these may reach the network -- including
    # while the first is still in flight.
    assert directory_.schedule_refresh() is False
    assert directory_.schedule_refresh() is False
    await settle(directory_)

    assert len(calls) == 1
    assert [entry["host"] for entry in directory_.current()] == [
        "neodb.social",
        "eggplant.place",
        "minreol.dk",
    ]

    # Still inside the interval once the first has finished.
    assert directory_.schedule_refresh() is False
    assert len(calls) == 1


async def test_the_floor_lifts_once_the_interval_has_passed():
    calls: list[str] = []
    directory_ = directory(calls=calls, interval=0.0)

    assert directory_.schedule_refresh() is True
    await settle(directory_)
    assert directory_.schedule_refresh() is True
    await settle(directory_)

    assert len(calls) == 2


async def test_a_failing_refresh_does_not_reset_the_floor():
    # Otherwise a feed returning 503 would be retried on every pairing code,
    # which is exactly the stampede the floor exists to prevent.
    calls: list[str] = []
    directory_ = directory(status=503, calls=calls, interval=60.0)

    assert directory_.schedule_refresh() is True
    await settle(directory_)
    assert directory_.schedule_refresh() is False

    assert len(calls) == 1


async def test_an_empty_url_fetches_nothing():
    calls: list[str] = []
    pinned = InstanceDirectory("", transport=servers_transport(calls=calls))

    assert pinned.schedule_refresh() is False
    assert calls == []
    assert pinned.current() == KNOWN_INSTANCES


def test_generating_a_code_asks_for_a_refresh():
    class Counting(InstanceDirectory):
        def __init__(self):
            super().__init__("")
            self.asked = 0

        def schedule_refresh(self) -> bool:
            self.asked += 1
            return True

    counter = Counting()
    client, _ = build(instances=counter)

    assert open_session(client).status_code == 201
    assert counter.asked == 1
    # Every code asks; the directory itself decides whether to go out.
    assert open_session(client).status_code == 201
    assert counter.asked == 2


def test_a_rejected_code_request_asks_for_nothing():
    class Counting(InstanceDirectory):
        def __init__(self):
            super().__init__("")
            self.asked = 0

        def schedule_refresh(self) -> bool:
            self.asked += 1
            return True

    counter = Counting()
    client, _ = build(instances=counter)

    # No code was generated, so there is no picker about to be shown.
    assert open_session(client, client_name="  ").status_code == 400
    assert counter.asked == 0


def test_a_broken_feed_cannot_break_code_generation():
    # The device is asking for a pairing code, not for the instance list. A feed
    # that is down must be invisible to it.
    client, _ = build(instances=directory(status=503, interval=0.0))

    for _ in range(3):
        assert open_session(client).status_code == 201


def test_the_join_page_offers_whatever_the_directory_holds():
    pinned = InstanceDirectory(
        "", seed=[{"host": "minreol.dk", "name": "Minreol", "note": "da"}]
    )
    client, _ = build(instances=pinned)
    code = open_session(client).json()["code"]

    page = client.get(f"/{code}")

    assert page.status_code == 200
    assert 'value="minreol.dk"' in page.text
    assert "Minreol" in page.text
    # The built-in seed was replaced, not appended to.
    assert 'value="eggplant.place"' not in page.text


def test_a_bad_port_is_a_message_not_a_crash():
    # Reachable from the join form's "another instance" box.
    with pytest.raises(NeoDBError):
        normalize_instance("ok.example:notaport")
