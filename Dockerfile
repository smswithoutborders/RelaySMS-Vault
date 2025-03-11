FROM python:3.13.1-slim as base

WORKDIR /vault

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    apache2 \
    apache2-dev \
    python3-dev \
    default-libmysqlclient-dev \
    supervisor \
    libsqlcipher-dev \
    libsqlite3-dev \
    git \
    curl \
    pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --disable-pip-version-check --quiet --no-cache-dir --force-reinstall -r requirements.txt

COPY . .

RUN make build-setup

FROM base AS production

ENV MODE=production

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
