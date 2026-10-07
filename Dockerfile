# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS wheels
WORKDIR /build
COPY requirements.txt /build/requirements.txt
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential gcc libffi-dev libssl-dev \
    && python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels -r /build/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    USE_GUNICORN=1 \
    DOCKER_MODE=1 \
    WIREGUARD_CONF_PATH=/etc/wireguard

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates curl git iproute2 iptables iputils-ping jq kmod nftables \
       openssl procps rsync tzdata unzip wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=wheels /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

WORKDIR /app
COPY . /app
RUN chmod 0755 /app/docker/entrypoint.sh \
    && mkdir -p /app/instance /etc/wireguard

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python", "app.py"]
