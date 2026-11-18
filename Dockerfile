# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Shamir's Secret Sharing toolkit — minimal, non-root runtime image.
#
#   docker build -t sss .
#   docker run --rm -it -v "$PWD:/data" sss split --secret "hello" -k 3 -n 5
#   docker run --rm -it -v "$PWD:/data" sss vault-lock /data/backup.tar.gz -k 3 -n 5
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code and metadata.
COPY pyproject.toml README.md THEORY.md LICENSE main.py ./
COPY core ./core
COPY cli ./cli
COPY simulation ./simulation
RUN pip install --no-cache-dir --no-deps .

# Run as an unprivileged user; secrets never touch root-owned files.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin sss \
    && chown -R sss:sss /app
USER sss

ENTRYPOINT ["sss"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Test stage: docker build --target test .
# ---------------------------------------------------------------------------
FROM runtime AS test

USER root
RUN pip install --no-cache-dir pytest
COPY tests ./tests
USER sss
CMD ["pytest", "-q"]
