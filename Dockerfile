# syntax=docker/dockerfile:1
#
# Two stages so the runtime image carries no build tooling. The wheels are
# installed into a virtualenv and the app is copied in as files rather than an
# installed package, so the image can be rebuilt without a network round trip to
# a package index at start time.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Copied on its own so the dependency layer is cached until a pin changes.
COPY requirements.txt ./

# wheel gives us a compiler for any sdist-only dependency, then it is discarded
# together with this stage.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip wheel \
    && /opt/venv/bin/pip install -r requirements.txt


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app/src \
    DATABASE_PATH=/data/uptimebot.db \
    BIND_HOST=0.0.0.0 \
    PORT=8000 \
    TZ=Asia/Jakarta

# curl is only here for the healthcheck; nothing else in the image needs it.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
COPY src/uptimebot ./src/uptimebot
COPY config ./config

# Only the data directory is writable. /app stays root-owned so a compromised
# process cannot rewrite its own code, and /data is a volume so a container
# rebuild does not discard the probe history and the outage durations.
# PYTHONDONTWRITEBYTECODE=1 is what makes this possible: with bytecode writing
# on, Python would need a writable /app.
RUN mkdir -p /data \
    && useradd --system --uid 10001 --home-dir /app uptimebot \
    && chown -R uptimebot:uptimebot /data

# The group that owns the bind-mounted secret files on the host. Compose mounts
# a file-backed secret with the host file's ownership intact, so the mode is not
# something this image can relax from the inside -- the container has to match
# whatever uid the operator gave those files. Naming the group here gives
# install.sh something concrete to chgrp to, and GID_SECRET is what the process
# falls back to as its primary group.
# GID_SECRET is the gid that owns the bind-mounted secret files on the host.
# Compose mounts a file-backed secret with the host file's ownership intact, so
# the mode is not something this image can relax from the inside -- the container
# has to be able to read the files under the mode the operator chose. The group
# is created at that gid and made the app user's primary group, so a 640 file
# owned by <installer>:<GID_SECRET> is readable in here and unreadable to anyone
# else on the host. install.sh passes `id -g` here so no chgrp or root is needed.
ARG GID_SECRET=1000
RUN groupadd --gid "$GID_SECRET" --system uptimebot-secrets \
    && usermod --gid "$GID_SECRET" uptimebot \
    && chown -R uptimebot:"$GID_SECRET" /data
ENV GID_SECRET="$GID_SECRET"

USER uptimebot

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8000/healthz || exit 1

CMD ["python", "-m", "uptimebot", "serve"]
