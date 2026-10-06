#!/usr/bin/env bash
#
# UptimeBot installer for Debian/Ubuntu servers.
#
#   sudo ./install.sh --domain monitor.example.com --email you@example.org
#
# What it does, in order:
#   1. checks Docker, Compose v2 and that ports 80/443 are actually free
#   2. refuses to continue with placeholder domain/email, because a silent ACME
#      failure is the single most confusing way this stack can fail to come up
#   3. creates .env, and generates the two secrets it owns (session key and
#      bcrypt password hash) with 0600 permissions
#   4. adds the port 80 mapping Linux can afford and Windows cannot
#   5. builds, starts, waits for the health check, then prints what to do next
#
# Safe to re-run: existing .env and existing secrets are never overwritten.
#
set -euo pipefail

DOMAIN=""
EMAIL=""
SKIP_PORT_CHECK=0
ASSUME_YES=0
NO_PORT_80=0
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Usage: install.sh --domain HOSTNAME --email ADDRESS [options]

Required for a public deployment:
  --domain HOSTNAME   the subdomain Caddy issues a certificate for, with a DNS
                      A/AAAA record already pointing at this machine
  --email ADDRESS     a real mailbox, used for the ACME account

Options:
  --skip-port-check   do not test whether 80/443 are bindable
  --no-port-80        never publish port 80; use this when nginx or another
                      server already owns it. Certificate issuance then goes
                      through TLS-ALPN-01 on 443, which needs nothing else.
  -y, --yes           do not prompt for the admin password
  -h, --help          show this message

For a local trial with no public DNS, omit --domain: the stack is then served at
https://localhost with an internal CA that browsers do not trust by default.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --email)  EMAIL="${2:-}";  shift 2 ;;
        --skip-port-check) SKIP_PORT_CHECK=1; shift ;;
        --no-port-80) NO_PORT_80=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

# ---------------------------------------------------------------- environment

say "Checking prerequisites"

[ "$(uname -s)" = "Linux" ] || die "this installer targets Linux; found $(uname -s)"
command -v docker >/dev/null 2>&1 || die "docker is not installed: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (the 'docker-compose' v1 script does not support 'secrets')"
docker info >/dev/null 2>&1 || die "cannot talk to the docker daemon; try: sudo systemctl start docker"

DOCKER_COMPOSE="docker compose"
printf '    docker: %s\n' "$(docker --version)"
printf '    compose: %s\n' "$(docker compose version --short)"

# ------------------------------------------------------------------- hostname

PUBLIC_HOST="localhost"
PUBLIC_URL="https://localhost"
ACME_EMAIL=""

if [ -n "$DOMAIN" ]; then
    # Refuse the placeholders. Let's Encrypt answers "invalidContact ...
    # forbidden domain \"example.com\"" for the address and then serves no
    # certificate at all, so the site looks broken with no obvious cause.
    case "$DOMAIN" in
        *example.com|*example.org|*.example|localhost)
            die "--domain '$DOMAIN' is a placeholder; Caddy cannot get a certificate for it" ;;
    esac
    case "$DOMAIN" in
        *.*) : ;;
        *) die "--domain '$DOMAIN' is not fully qualified" ;;
    esac
    PUBLIC_HOST="$DOMAIN"
    PUBLIC_URL="https://$DOMAIN"
    [ -n "$EMAIL" ] || die "--email is required together with --domain"
    case "$EMAIL" in
        *@*.*) : ;;
        *) die "--email '$EMAIL' does not look like an address" ;;
    esac
    case "$EMAIL" in
        *example.com|*example.org)
            die "--email '$EMAIL' is rejected by Let's Encrypt (forbidden domain)" ;;
    esac
    ACME_EMAIL="$EMAIL"
else
    warn "no --domain given: serving https://localhost with an internal CA"
    warn "browsers will warn about the certificate; this is not a public deployment"
fi

# ------------------------------------------------------------------ file check

say "Preparing configuration"

if [ ! -f .env ]; then
    cp .env.example .env
    printf '    created .env from .env.example\n'
else
    printf '    .env already exists, keeping it\n'
fi

set_env() {
    # Replace the whole line if the key exists, otherwise append it.
    local key="$1" value="$2"
    if grep -qE "^${key}=" .env; then
        # Use a temp file: sed -i on a file other lines contain slashes in.
        local tmp
        tmp="$(mktemp)"
        awk -v k="$key" -v v="$value" '
            $0 ~ "^" k "=" { print k "=" v; next }
            { print }
        ' .env >"$tmp" && mv "$tmp" .env
    else
        printf '%s=%s\n' "$key" "$value" >>.env
    fi
}

set_env PUBLIC_HOST "$PUBLIC_HOST"
set_env PUBLIC_URL "$PUBLIC_URL"
if [ -n "$ACME_EMAIL" ]; then
    set_env ACME_EMAIL "$ACME_EMAIL"
fi
# The app must be reached over TLS for the session cookie to be Secure.
set_env COOKIE_SECURE true
# Caddy replaces X-Forwarded-For, so trusting it is safe here and keeps the login
# throttle from collapsing into one shared bucket.
set_env TRUST_PROXY true

# --------------------------------------------------------------------- secrets

mkdir -p secrets

# The password arrives through the container environment rather than as a command
# line argument, so it does not show up in `ps` output.
write_secret() {
    local name="$1"
    if [ -s "secrets/$name" ]; then
        # Re-run safety: never overwrite what already exists. Tighten the mode
        # anyway, since a hand-made or previously world-readable file would
        # otherwise stay that way.
        chmod 600 "secrets/$name"
        printf '    secrets/%s already exists, keeping it\n' "$name"
        return 0
    fi
    case "$name" in
        ui_password_hash)
            local password=""
            if [ "$ASSUME_YES" -eq 1 ]; then
                die "--yes needs an existing secrets/ui_password_hash, or drop --yes to be prompted"
            fi
            printf '    admin password for the web UI (min 10 characters, not echoed): '
            read -r -s password
            printf '\n'
            [ "${#password}" -ge 10 ] || die "password must be at least 10 characters"
            printf '    confirm: '
            local again=""
            read -r -s again
            printf '\n'
            [ "$password" = "$again" ] || die "the two passwords do not match"
            # An env var of a transient container, not an argv entry.
            #
            # $DOCKER_COMPOSE, not DOCKER_COMPOSE: the variable holds two words
            # ("docker compose") and the bare form is a command not found.
            $DOCKER_COMPOSE run --rm --no-deps -T \
                -e "UPTIMEBOT_PW=$password" \
                --entrypoint python \
                uptimebot -c 'import os,sys; sys.path.insert(0,"/app/src"); from uptimebot.web.auth import hash_password; sys.stdout.write(hash_password(os.environ["UPTIMEBOT_PW"]))' \
                >"secrets/$name"
            unset password again
            ;;
        secret_key)
            $DOCKER_COMPOSE run --rm --no-deps -T \
                --entrypoint python \
                uptimebot -c 'import sys; sys.path.insert(0,"/app/src"); from uptimebot.settings import generate_secret_key; sys.stdout.write(generate_secret_key())' \
                >"secrets/$name"
            ;;
        *)
            # The Discord values are the operator's to paste from Discord itself.
            : >"secrets/$name"
            printf '    created empty secrets/%s, fill it in before enabling alerts\n' "$name"
            ;;
    esac
    chmod 600 "secrets/$name"
}

say "Generating secrets"
write_secret secret_key
write_secret ui_password_hash
# Created empty on purpose: these are credentials that only exist inside Discord.
[ -e secrets/discord_webhook ] || { : >secrets/discord_webhook; printf '    created empty secrets/discord_webhook\n'; }
[ -e secrets/discord_bot_token ] || { : >secrets/discord_bot_token; printf '    created empty secrets/discord_bot_token\n'; }
chmod 600 secrets/discord_webhook secrets/discord_bot_token

if [ ! -s secrets/ui_password_hash ]; then
    die "secrets/ui_password_hash came out empty; cannot continue"
fi

# ------------------------------------------------------------------- port check

if [ "$SKIP_PORT_CHECK" -eq 0 ]; then
    say "Checking ports 80 and 443"
    for p in 80 443; do
        if ss -ltn "sport = :$p" 2>/dev/null | tail -n +2 | grep -q .; then
            warn "port $p is already in use by another process; stop it or the stack will not bind"
        else
            printf '    port %s free\n' "$p"
        fi
    done
fi

# -------------------------------------------------------------------- compose

# Windows cannot bind 80 (HTTP.sys/WinRM reserve it), which is why the base file
# omits it. On Linux it is free, and publishing it enables the ACME HTTP-01
# challenge plus the http -> https redirect.
#
# On a host where nginx or Apache already owns 80, publishing it here would make
# `docker compose up` fail outright. --no-port-80 skips the mapping entirely and
# Caddy uses TLS-ALPN-01 on 443 instead. The trade-off is that visitors must type
# https:// (or Caddy's plain-HTTP 308 redirect never gets a chance to run,
# because nothing is listening on 80 to issue it).
OVERRIDE="docker-compose.override.yml"

if [ "$NO_PORT_80" -eq 1 ]; then
    warn "not publishing port 80 (--no-port-80); ACME will use TLS-ALPN-01 on 443"
    warn "if another server already answers on 80, it must not also try to serve this domain"
    rm -f "$OVERRIDE"
else
    cat >"$OVERRIDE" <<'YAML'
# Generated by install.sh. Compose merges this over docker-compose.yml and
# appends the port, so 443 keeps its mapping and 80 is added back.
services:
  caddy:
    ports:
      - "80:80"
YAML
    printf '    wrote %s\n' "$OVERRIDE"
fi

say "Validating the compose configuration"
$DOCKER_COMPOSE config --quiet || die "compose configuration is invalid"

# ----------------------------------------------------------------------- start

say "Building and starting"
$DOCKER_COMPOSE up -d --build

say "Waiting for the health check"
for i in $(seq 1 60); do
    state="$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q uptimebot)" 2>/dev/null || echo unknown)"
    case "$state" in
        healthy)
            printf '    healthy after %ss\n' "$((i * 5))"
            break
            ;;
        unhealthy)
            die "the app reported unhealthy; see: docker compose logs uptimebot"
            ;;
    esac
    sleep 5
done
[ "$state" = "healthy" ] || die "timed out waiting for the health check; see: docker compose logs uptimebot"

# --------------------------------------------------------------------- summary

say "Done"
printf '    URL          %s\n' "$PUBLIC_URL"
printf '    username     %s\n' "$(grep -E '^UI_USERNAME=' .env | cut -d= -f2- | head -n1)"
printf '    password     the one you entered during install\n'

cat <<'NEXT'

Next steps
  1. Alerts. Paste the Discord webhook URL into secrets/discord_webhook, then:
       echo -n 'https://discord.com/api/webhooks/<id>/<token>' | sudo tee secrets/discord_webhook >/dev/null
       sudo chmod 600 secrets/discord_webhook
       sudo docker compose up -d
     Verify with: curl -s http://127.0.0.1:8000/healthz | grep -o '"discord_webhook":[a-z]*'
     (that is inside the container: sudo docker compose exec -T uptimebot \\
        python -c "import json,urllib.request;print(json.load(urllib.request.urlopen('http://127.0.0.1:8000/healthz'))['discord_webhook'])")

  2. Add monitors:
       sudo docker compose exec -T uptimebot \\
         python -m uptimebot import-config /app/config/monitors.example.yml

  3. Point DNS. PUBLIC_HOST must already resolve to this machine or certificate
     issuance fails and the site serves nothing. Check with:
       dig +short "$PUBLIC_HOST"

  4. Back up. The uptime history lives in one SQLite file:
       sudo docker compose exec -T uptimebot python -c \\
         "import sqlite3; s=sqlite3.connect('/data/uptimebot.db'); \\
          d=sqlite3.connect('/data/backup.db'); s.backup(d)"
       sudo docker compose cp uptimebot:/data/backup.db ./backup-$(date +%F).db

Commands
  docker compose logs -f uptimebot     application log
  docker compose ps                     status
  docker compose restart uptimebot      apply .env / secret changes
  docker compose down                   stop, keep data
  docker compose exec uptimebot python -m uptimebot check    config report
NEXT