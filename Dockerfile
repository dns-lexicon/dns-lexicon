FROM python:3.14.0-slim
LABEL org.opencontainers.image.authors="adferrand@github"

# Setup dependencies
RUN apt-get update \
 && apt-get -y install cron rsyslog git --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Install dns-lexicon
ARG LEXICON_VERSION=3.*
ENV LEXICON_VERSION="${LEXICON_VERSION}"
RUN pip install "dns-lexicon[full]==${LEXICON_VERSION}"

# Add and configure entrypoint
COPY --chmod=755 docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
