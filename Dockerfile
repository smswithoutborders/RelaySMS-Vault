FROM python:3.13.0-slim as base

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
    rm -rf /var/lib/apt/lists/*

WORKDIR /

COPY . .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

RUN pip install --disable-pip-version-check --quiet --no-cache-dir --force-reinstall -r requirements.txt 

FROM base AS production

ENV MODE=production

CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
