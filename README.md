# UptimeBot

Uptime, downtime-duration and SSL-expiry monitoring with Discord reporting and a
small web admin UI. One container, one SQLite file, no external services.

Built for 10–50 endpoints: enough that a person has to be told when one of them
is unwell, few enough that the whole state fits in a file you can back up by
copying it.

## What it does

- **Uptime monitoring** over HTTP/HTTPS with configurable interval, timeout,
  method, expected status codes, a response keyword, and request headers pulled
  from environment variables.
- **Anti-flap alerting**: a failure only pages someone after it repeats N times
  (default 3), so one dropped packet does not wake anybody up.
- **Downtime duration** that survives a restart, and **healthy-run duration** for
  the same reason. "Down for 2 hours" stays "down for 2 hours" after a redeploy.
- **Uptime percentage** over 24 h / 7 d / 30 d, latency average and p95, and a
  probe history chart.
- **SSL expiry** warnings at 30/14/7/1 days and on expiry. Each bracket warns
  once; it only warns again when the situation gets more urgent. A failed
  handshake is silent rather than a false alarm.
- **Discord reporting** through a webhook. Mentions go in the top-level
  `content` field only, with `allowed_mentions` explicitly empty, so a monitor
  name or a response body can never ping a whole channel.
- **@username resolution**: type `@budi` in the UI and it becomes a numeric user
  ID, using a bot token to read recent channel history. Optional — the UI falls
  back to entering an ID by hand.
- **Reminder cadence**: while a monitor is down, the PIC is re-pinged every 30
  minutes so the incident cannot be quietly forgotten.

## Quick start

### Docker (recommended)

```bash
cp .env.example .env
# Fill in DISCORD_WEBHOOK_URL, UI_PASSWORD_HASH, SECRET_KEY, PUBLIC_HOST.

docker compose up -d
docker compose logs -f uptimebot
```

Then open the site over HTTPS. The first login uses `UI_USERNAME` and the plain
password whose hash you put in `UI_PASSWORD_HASH`.

Two commands to generate the secrets:

```bash
docker compose run --rm uptimebot python -m uptimebot genkey
docker compose run --rm uptimebot python -m uptimebot hash-password
```

### Behind a Cloudflare Tunnel (no inbound ports)

Use this when the host has no public IP and no port is forwarded to it, so Caddy
cannot answer an ACME challenge and visitors cannot reach it at all. A Cloudflare
Tunnel inverts the flow: `cloudflared` dials *out* to Cloudflare and Cloudflare
routes the public hostname down that connection, so nothing is published and no
public certificate is required.

```bash
# 1. Install the connector (Debian/Ubuntu, x86_64).
curl -fsSL -o /tmp/cloudflared.deb \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i /tmp/cloudflared.deb

# 2. Zero Trust > Networks > Tunnels > Create a tunnel > Cloudflared.
#    Copy the token from the install page, then:
sudo cloudflared service install <TOKEN>

# 3. On the same tunnel add a Public Hostname:
#      Subdomain/Domain : monitoring.example.com
#      Service          : https://localhost:<caddy-port>
#    where <caddy-port> is the host side of the Caddy 443 mapping in
#    docker-compose.yml — 443 by default, or the non-standard port from your
#    docker-compose.override.yml when something else already owns 443.
#    Leave "No TLS Verify" off if you trust the internal CA (below).
```

Then point the stack at the tunnel Caddyfile in `.env`:

```ini
PUBLIC_URL=https://monitoring.example.com
CADDYFILE=./Caddyfile.cloudflared
```

`PUBLIC_HOST` stays `localhost`: `cloudflared` connects to Caddy over the
loopback, so the origin certificate only has to match `localhost`. The public
name lives in `PUBLIC_URL`, which is what the app uses to build absolute links.

`Caddyfile.cloudflared` serves that single `localhost` site with Caddy's
**internal** CA (no certificate is fetched from Let's Encrypt, so `ACME_EMAIL`
is unused) and takes the client IP from `CF-Connecting-IP`, which keeps the
login throttle per visitor instead of collapsing everyone into the tunnel's own
address. Because that origin certificate is internal, tell `cloudflared` to
trust Caddy's root:

```bash
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt \
  | sudo tee /usr/local/share/ca-certificates/caddy-uptimebot.crt >/dev/null
sudo update-ca-certificates
sudo systemctl restart cloudflared
```

(Or turn on **No TLS Verify** for the public hostname in the dashboard instead.)
Finally:

```bash
docker compose up -d
curl -fsS https://monitoring.example.com/healthz
```

### Without Docker

Needs Python 3.12 or newer.

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .          # makes `python -m uptimebot` importable
export $(grep -v '^#' .env | xargs)   # or use your own env loader
python -m uptimebot import-config config/monitors.example.yml   # optional
python -m uptimebot serve
```

The editable install is not optional: `requirements.txt` pins the dependencies
but does not install this project, and the package lives under `src/`, so
without it `python -m uptimebot` fails with "No module named uptimebot".

## Configuration

Everything lives in environment variables; see `.env.example` for the annotated
list. Monitor definitions live in the **database**, not in a file, because the
web UI edits them and a config file would mean write races between the UI and
the scheduler.

`config/monitors.example.yml` is only an import format for the first run:

```bash
python -m uptimebot import-config config/monitors.example.yml
```

The import is idempotent — re-running it skips monitors that already exist and
never overwrites a monitor you have since edited in the UI.

### CLI

```bash
python -m uptimebot serve              # run the web app and the scheduler
python -m uptimebot check              # validate configuration, then exit
python -m uptimebot genkey             # a session-signing key
python -m uptimebot hash-password      # a bcrypt hash for UI_PASSWORD_HASH
python -m uptimebot import-config FILE # seed monitors from YAML
```

`check` is the one to run first when something looks wrong: it reports missing
or malformed configuration without starting anything.

## Security notes

The web UI fetches URLs that a logged-in user types, and it runs wherever it is
deployed — on a host that can reach the private network, on a cloud VM that can
reach the instance metadata endpoint. Three layers guard that:

1. The URL as typed is checked, so a private address is refused in the browser.
2. The hostname is resolved immediately before connecting, and each resulting
   address is checked, which catches a name that only resolves privately.
3. The address the socket actually reached is checked after connecting, which
   catches a DNS rebind between the lookup and the connection.

This is defence in depth, not strict address pinning — pinning would need a
custom resolver wired into httpcore. When the third check fires, the response is
discarded rather than read.

Internal targets are opt-in per monitor (`allow_private_network`).

Login is rate limited per client IP, the password is stored only as a bcrypt
hash, and the session is a signed `HttpOnly` `SameSite=Lax` cookie whose
signature is bound to the current password hash — so rotating the password logs
everybody out without a session store. Every state-changing form echoes a CSRF
token; `/login` and `/logout` are the two deliberate exceptions, since neither
can be abused without a session to abuse and a cross-site post cannot carry a
`SameSite=Lax` cookie.

The throttle's client key is the immediate peer by default. Behind Caddy that
would be the proxy for everybody, so `TRUST_PROXY` is on in
`docker-compose.yml` and the Caddyfile *replaces* `X-Forwarded-For` rather than
appending to it — which is what makes trusting it safe. A proxy that appends to
a client-supplied header would let anyone mint a fresh throttle budget per
request; set `TRUST_PROXY=false` if you ever front the app with one.

The app publishes no port in `docker-compose.yml`; Caddy is the only way in, and
it terminates TLS.

## Operations

### Backups

The state that matters is all in one file. The image has no `sqlite3` CLI, so
this uses the Python driver already in the image. `sqlite3`'s online backup API
takes a consistent copy while the app keeps running, which a plain file copy
does not:

```bash
docker compose exec -T uptimebot python - <<'PY'
import sqlite3
src = sqlite3.connect("/data/uptimebot.db")
dst = sqlite3.connect("/data/backup.db")
with dst:
    src.backup(dst)
dst.close()
src.close()
print("backup written")
PY
docker cp uptimebot:/data/backup.db ./backup-$(date +%F).db
```

The copy lands in the same volume. Move it off the host afterwards; a backup
that only exists on the machine it protects is not a backup.

Keep the Caddy volumes too, or a rebuilt container will have to re-request
certificates and can hit Let's Encrypt rate limits.

### Upgrades

```bash
docker compose build --pull
docker compose up -d
```

The schema is applied on start, and probe history is pruned to `RETENTION_DAYS`
daily.

> The schema is created with `CREATE TABLE IF NOT EXISTS`, so a **fresh**
> database always matches the current code. An **existing** database is not
> migrated: columns added after a deployment — `up_since` and
> `checks.failure_kind` — will be missing. Back up before upgrading, and check
> `PRAGMA table_info(monitor_state)` if the dashboard shows a missing duration.

### Health

`GET /healthz` returns 503 while the scheduler is not running, so a container
with a dead probe loop is taken out of rotation instead of serving a dashboard
that quietly stopped updating.

## Development

```bash
.venv/bin/pip install -r requirements.txt pytest pytest-asyncio
.venv/bin/python -m pytest tests -q
```

The test suite covers the alerting state machine, the SSRF guard, state and
history persistence, the scheduler lifecycle, and the web layer's auth, CSRF
and rendering. Tests use a temporary database each, so they never touch
`data/`.

## Layout

```
src/uptimebot/
  settings.py          environment parsing and validation
  models.py            domain types, SSL severity, formatting
  db/                  schema, repositories, aiosqlite wrapper
  monitor/
    checker.py         the HTTP probe
    sslcheck.py        certificate inspection
    ssrf.py            outbound URL guard
    statemachine.py    alerting rules, pure and synchronous
    scheduler.py       per-monitor tasks and reconciliation
  discord/             webhook delivery, embeds, mention resolution
  web/                 FastAPI app, auth, forms, routes, templates
  cli.py               command line entry point
```
