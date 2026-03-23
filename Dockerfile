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

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kaskad-oracle /usr/local/bin/kaskad-oracle

# Nitro Enclave has no network — all I/O goes through VSOCK.
# The oracle will connect to the VSOCK proxy on the host for:
#   - HTTP requests to CEX APIs
#   - RPC calls to the blockchain
#   - Attestation document retrieval (NSM)
#
# Environment variables are injected at EIF build time or via VSOCK.

ENV RUST_LOG=info
ENV ENCLAVE_MODE=1

ENTRYPOINT ["/usr/local/bin/kaskad-oracle"]
