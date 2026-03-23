# ── Stage 1: Build the oracle binary (static, musl) ──────────────────
FROM rust:1.90-alpine3.20 AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Build static binary (musl target)
RUN cargo build --release --target x86_64-unknown-linux-musl

# ── Stage 2: Minimal runtime image ───────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates socat

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kaskad-oracle /usr/local/bin/kaskad-oracle

# Nitro Enclave has no network — all I/O goes through VSOCK.
# The oracle will connect to 127.0.0.1:5000 locally, which socat bridges
# securely to the Host OS VSOCK interface for transparent proxying.

RUN echo '#!/bin/sh' > /init.sh && \
    echo 'socat TCP-LISTEN:5000,fork,reuseaddr VSOCK-CONNECT:3:5000 &' >> /init.sh && \
    echo 'exec /usr/local/bin/kaskad-oracle' >> /init.sh && \
    chmod +x /init.sh

ENV RUST_LOG=info
ENV ENCLAVE_MODE=1

ENTRYPOINT ["/init.sh"]
