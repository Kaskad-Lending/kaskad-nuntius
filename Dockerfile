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

RUN apk add --no-cache ca-certificates iproute2

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kaskad-oracle /usr/local/bin/kaskad-oracle

# Nitro Enclave has no network — the Rust binary includes a built-in
# VSOCK→TCP bridge that tunnels reqwest HTTP CONNECT requests to the Host OS.
# TLS termination happens natively inside the enclave boundary.

ENV RUST_LOG=info
ENV ENCLAVE_MODE=1

# Nitro Enclave boots with lo interface down. Must bring it up
# before the oracle can bind to 127.0.0.1 (VSOCK→TCP bridge).
COPY <<'EOF' /entrypoint.sh
#!/bin/sh
set -e

# Bring up loopback (required for VSOCK→TCP bridge on 127.0.0.1)
ip link set lo up

# Verify hardware RNG is active (NSM provides true entropy).
# Fallback to RDRAND/RDSEED is insecure — abort if nsm-hwrng missing.
RNG_CURRENT=$(cat /sys/devices/virtual/misc/hw_random/rng_current 2>/dev/null || echo "none")
if [ "$RNG_CURRENT" != "nsm-hwrng" ]; then
  echo "FATAL: Hardware RNG is '$RNG_CURRENT', expected 'nsm-hwrng'"
  echo "Enclave key generation would be insecure. Aborting."
  exit 1
fi

exec /usr/local/bin/kaskad-oracle
EOF
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
