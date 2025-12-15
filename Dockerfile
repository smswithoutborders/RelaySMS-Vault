FROM python:3.15.0a2-slim AS base

WORKDIR /vault

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt \
    --mount=type=cache,sharing=locked,target=/var/lib/apt \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    apache2 \
    apache2-dev \
    default-libmysqlclient-dev \
    supervisor \
    libsqlcipher-dev \
    libsqlite3-dev \
    git \
    vim \
    curl \
    pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN --mount=type=cache,sharing=locked,target=/root/.cache/pip \
    pip install --disable-pip-version-check -r requirements.txt

COPY . .

RUN make build-setup

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

FROM base AS production

ENV MODE=production

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

FROM base AS development

ENV MODE=development

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
