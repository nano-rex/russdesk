# Build the Rust server (standard library + vendored SQLite only).
FROM rust:1.83-bookworm AS build
WORKDIR /src
COPY rust/ ./
RUN cargo build --release --locked

FROM debian:bookworm-slim

ENV RUSSDESK_DATA_DIR=/data \
    RUSSDESK_PORT=31114 \
    RUSSDESK_STATIC_DIR=/app/static

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin russdesk \
    && mkdir -p /data /app \
    && chown russdesk /data

COPY --from=build /src/target/release/russdesk /usr/local/bin/russdesk
COPY --from=build /src/static /app/static

WORKDIR /app
USER russdesk
VOLUME /data
EXPOSE 31114
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["russdesk", "--healthcheck"]
CMD ["russdesk"]
