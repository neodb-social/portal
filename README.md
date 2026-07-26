# NeoDB Portal

A small pairing service that lets a device with an awkward keyboard sign in to
[NeoDB](https://neodb.net) by showing a QR code.

It exists because the honest OAuth flow is miserable on an e-reader: you have to
type a server address, then read a long authorization code off a phone and enter
it a character at a time on an e-ink keyboard. Instead, the device shows a short
link, you scan it, you sign in on the phone where signing in is easy, and the
device collects the result.

```
 e-reader                    portal                     your NeoDB instance
    │                          │                                │
    │  POST /api/session       │                                │
    ├─────────────────────────►│  join URL + fetch token        │
    │◄─────────────────────────┤                                │
    │                          │                                │
    │  shows QR of join URL    │                                │
    │                          │                                │
    │        (you scan it with your phone)                      │
    │                          │◄── GET  /<code> ──── phone      │
    │                          │──► pick instance ──────────────►│
    │                          │                    authorize    │
    │                          │◄── GET /svc/callback ──────────┤
    │                          │──► exchange for token ─────────►│
    │                          │◄───────────────────────────────┤
    │  GET /api/session/<code> │                                │
    ├─────────────────────────►│  app + token credentials, once │
    │◄─────────────────────────┤  (session then forgotten)      │
```

## Nothing is stored

Pairing sessions live in a dictionary in memory, expire after 15 minutes, and
are dropped the moment the device collects them. There is no database, no disk
write, and no log of tokens.

That applies to the whole grant, not just the access token: the app credentials
and refresh token are handed over once and forgotten in the same breath. A
device that never comes back to collect them loses them at the 15-minute mark
along with the rest of the session.


## API

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/session` | device | Open a session. Requires a `client_name` form field. Returns `code`, `fetch_token`, `join_url`, `expires_in`. |
| `GET` | `/api/session/{code}` | device | `202` while pending, `200` with the credentials once ready (and forgets them). Needs `Authorization: Bearer <fetch_token>`. |
| `DELETE` | `/api/session/{code}` | device | Abandon a session early. |
| `GET` | `/{code}` | phone | Instance picker — see [Instance list](#instance-list). |
| `POST` | `/{code}` | phone | Redirects into the instance's OAuth flow. |
| `GET` | `/svc/callback` | phone | OAuth return; exchanges the code for a token. |
| `GET` | `/healthz` | ops | Liveness plus a count of pending sessions. |
| `GET` | `/robots.txt` | crawlers | `Disallow: /`. |

A device that polls should back off: `202` means "auth has not finished
yet", which may be a minute or two.

### Opening a session

```
POST /api/session
Content-Type: application/x-www-form-urlencoded

client_name=Kobo+Clara
```

```json
{
  "code": "n7kq2vx4mb",
  "fetch_token": "…",
  "join_url": "https://p.neodb.net/n7kq2vx4mb",
  "expires_in": 900
}
```

`join_url` is the complete URL to render as a QR code — origin and pairing code,
nothing else to assemble.

`client_name` is a required form field: it is whatever the device calls itself,
it is registered with the instance the visitor picks, and it appears on that
instance's consent screen. "Kobo Clara" tells the person approving it something;
a name belonging to this service would not. Up to 64 printable characters; a
missing one is `422` and an unusable one `400`.

Devices naming themselves differently get separate app registrations, so nobody
is ever asked to approve someone else's device.

### Collecting the result

The `200` carries everything needed to keep talking to the instance afterwards,
and is the only time any of it is offered:

```json
{
  "status": "ready",
  "instance": "https://neodb.social",
  "client_name": "Kobo Clara",
  "client_id": "…",
  "client_secret": "…",
  "access_token": "…",
  "refresh_token": "…",
  "token_type": "Bearer",
  "scope": "read write",
  "token_expires_in": 5184000,
  "username": "song",
  "display_name": "Song"
}
```

The app credentials come along because this service keeps nothing to look them
up with later, and the device needs them to re-authorize or refresh on its own.

`refresh_token`, `token_type`, `scope` and `token_expires_in` are passed through
from the instance and may be `null`. NeoDB sends none of them: its access tokens
do not expire and end only by being revoked. The fields are there for servers
that do issue them.

`token_expires_in` is the access token's own lifetime, not the pairing
session's; the `expires_in` on a `202` is the session's.


## Instance list

The picker offers the servers published in [NeoDB's own
list](https://neodb.net/servers.json); any other host can still be typed in.

The list is refreshed in the background when a device asks for a pairing code —
the one moment a stale list is about to become visible, and the last moment it
can still be fixed before the visitor scans the QR code. An idle process makes no
outbound requests at all.

Refreshes are floored at one attempt per `PORTAL_SERVERS_REFRESH` seconds,
whether they succeed or fail, so neither a burst of pairings nor a feed that is
down turns into a stampede. A refresh never blocks or fails the request that
triggered it, and a feed that is unreachable, malformed, or empty leaves the
previous list in place — the built-in one, if none has ever loaded.

The document is taken at its word rather than validated: it is published by the
same people who run this service, so it is not a trust boundary. One that does
not match the shape above is handled like an unreachable feed.


## Configuration

Put it behind TLS. The OAuth redirect URI is derived from `PORTAL_BASE_URL` and
is registered with each instance, so it must be the address users actually reach
— not the bind address.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORTAL_BASE_URL` | `https://p.neodb.net` | Public origin; `/svc/callback` is appended for OAuth. |
| `PORTAL_SESSION_TTL` | `900` | Session lifetime, seconds. |
| `PORTAL_MAX_SESSIONS` | `10000` | Upper bound on sessions held in memory. |
| `PORTAL_CREATE_RATE` | `20` | Sessions per client IP per minute. |
| `PORTAL_WEBSITE` | unset | Optional app website registered alongside the device's own name. |
| `PORTAL_SERVERS_URL` | `https://neodb.net/servers.json` | Published instance list for the picker. Empty pins the built-in list and makes the service fetch nothing. |
| `PORTAL_SERVERS_REFRESH` | `60` | Floor between refresh attempts, seconds. |
| `PORTAL_HOST` / `PORTAL_PORT` | `127.0.0.1` / `8080` | Bind address for the bundled runner. |
| `PORTAL_ALLOW_PRIVATE_HOSTS` | `false` | Development only — see below. |
| `PORTAL_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Whose `X-Forwarded-For` to trust. Widening it lets callers spoof past the rate limiter. |
| `SENTRY_DSN` | unset | Enables metrics. Nothing is reported without it. |
| `SENTRY_ENVIRONMENT` | unset | Environment tag. |


## Licence

AGPL-3.0
