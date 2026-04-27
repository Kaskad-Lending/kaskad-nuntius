# ── Stage 1: Build the oracle binary (static, musl) ──────────────────
# Digest-pinned (audit S-1). Tag-only references let a Docker Hub
# registry-tag mutation (or upstream republish) silently drift PCR0.
# Update by re-running:
#   curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull" | jq -r .token
#   curl -sI -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.oci.image.index.v1+json" \
#     https://registry-1.docker.io/v2/library/rust/manifests/1.90-alpine3.20 | grep -i docker-content-digest
FROM rust:1.90-alpine3.20@sha256:ef86f37c2819ebd1ecb1dbd7efda70c693cb013232688aa136a5a2f1e3b65e55 AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
# `include_str!("../config/assets.json")` means the file must be present at
# compile time. Baking it into the EIF puts its bytes into PCR0.
COPY config/ ./config/

# Build static binary (musl target)
RUN cargo build --release --target x86_64-unknown-linux-musl

# ── Stage 2: Minimal runtime image ───────────────────────────────────
# Digest-pinned (audit S-1). Same rationale as the builder stage.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

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
