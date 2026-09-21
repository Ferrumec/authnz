# syntax=docker/dockerfile:1
#
# authnz is edition 2024 (via typed-eventbus), which needs Cargo >= 1.85 —
# pinned to bookworm so the builder's glibc matches the debian:bookworm-slim
# runtime below (mirrors gitea-delivery-service's Dockerfile).
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
# Cargo.lock is copied when present (commit it for reproducible builds).
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --bin authnz

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home authnz
WORKDIR /app
COPY --from=build /src/target/release/authnz /usr/local/bin/authnz
# permissions.json is read at startup (PermissionSet::from_file) relative
# to the working directory — must ship alongside the binary.
COPY permissions.json ./permissions.json
COPY migrations ./migrations
USER authnz
# main.rs defaults to 127.0.0.1:8080 (local-safe); override for containers
# so the port is actually reachable from outside the container network.
ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["authnz"]
