# Build stage
FROM rust:1.99.1-trixie@sha256:542d25b2363937f9b513c6c7883a0f18b88b97c3e4c68aba9d8c0f9b6fdc2d63 AS builder

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang cmake protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Stamped into the binary (cli/src/update/channel.rs) so it knows it was
# installed via the Docker image.
ARG S2_BUILD_CHANNEL=docker
ARG S2_GIT_REV=unknown

# Use Docker BuildKit cache mounts for faster builds
RUN --mount=type=bind,source=api,target=/build/api \
    --mount=type=bind,source=common,target=/build/common \
    --mount=type=bind,source=pki-auth,target=/build/pki-auth \
    --mount=type=bind,source=lite,target=/build/lite \
    --mount=type=bind,source=resource-spec,target=/build/resource-spec \
    --mount=type=bind,source=sdk,target=/build/sdk \
    --mount=type=bind,source=storage,target=/build/storage \
    --mount=type=bind,source=testcontainers,target=/build/testcontainers \
    --mount=type=bind,source=cli,target=/build/cli \
    --mount=type=bind,source=Cargo.toml,target=/build/Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=/build/Cargo.lock \
    --mount=type=cache,id=s2-rust,sharing=locked,target=/build/target \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,sharing=locked,target=/usr/local/cargo/git \
    S2_BUILD_CHANNEL="${S2_BUILD_CHANNEL}" \
    S2_GIT_REV="${S2_GIT_REV}" \
    cargo build --locked --release --package s2-cli --bin s2

# Copy the binary from the cache volume
RUN --mount=type=cache,id=s2-rust,sharing=locked,target=/build/target \
    mkdir -p /output && \
    cp /build/target/release/s2 /output/s2

# Debug runtime - ubuntu with shell access
# Build with: docker build --target debug .
FROM ubuntu:latest AS debug

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /output/s2 /app/s2

ENTRYPOINT ["./s2"]

# Production runtime (default) - minimal distroless image running as non-root (UID 65532)
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

LABEL org.opencontainers.image.source="https://github.com/s2-streamstore/s2"
LABEL org.opencontainers.image.documentation="https://github.com/s2-streamstore/s2/releases"

WORKDIR /app

COPY --from=builder /output/s2 /app/s2

ENTRYPOINT ["./s2"]
