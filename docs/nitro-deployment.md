# Nitro Enclave Deployment

Step-by-step guide to build, deploy, and run the Kaskad Oracle inside an AWS Nitro Enclave.

## Prerequisites

- EC2 instance with Nitro Enclave support (e.g. `m5.xlarge`, `c5.xlarge`)
- Amazon Linux 2 or Ubuntu 22.04+
- `nitro-cli` installed
- Docker installed

```bash
# Install Nitro CLI (Amazon Linux 2)
sudo amazon-linux-extras install aws-nitro-enclaves-cli
sudo yum install aws-nitro-enclaves-cli-devel

# Enable Nitro Enclaves allocator
sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start nitro-enclaves-allocator.service

# Allocate memory for enclave (at least 512MB)
# Edit /etc/nitro_enclaves/allocator.yaml:
#   memory_mib: 512
#   cpu_count: 2
```

## 1. Build Docker Image

```bash
# On the EC2 instance (or in CI pipeline):
docker build -t kaskad-oracle:latest .

# Verify it runs
docker run --rm kaskad-oracle:latest --help
```

## 2. Build Enclave Image (EIF)

```bash
# Convert Docker image → Enclave Image Format
nitro-cli build-enclave \
  --docker-uri kaskad-oracle:latest \
  --output-file kaskad-oracle.eif

# Output includes PCR0, PCR1, PCR2 hashes:
#   Enclave Image successfully created.
#   {
#     "Measurements": {
#       "HashAlgorithm": "Sha384 { ... }",
#       "PCR0": "abc123...",   ← THIS goes into the smart contract
#       "PCR1": "def456...",
#       "PCR2": "..."
#     }
#   }
#
# SAVE THE PCR0 — you need it for contract deployment.
```

## 3. Start the VSOCK Proxy (on host)

```bash
# The proxy runs on the host and forwards HTTP from the enclave
python3 enclave/vsock_proxy.py 5000 &

# Or as a systemd service:
sudo cp enclave/vsock-proxy.service /etc/systemd/system/
sudo systemctl enable vsock-proxy
sudo systemctl start vsock-proxy
```

## 4. Run the Enclave

```bash
# Start the enclave
nitro-cli run-enclave \
  --eif-path kaskad-oracle.eif \
  --cpu-count 2 \
  --memory 512 \
  --enclave-cid 16

# Check status
nitro-cli describe-enclaves

# View console output (debug mode only)
nitro-cli console --enclave-id <enclave-id>
```

## 5. Deploy Contracts

```bash
# Use the PCR0 from step 2
export PCR0=0x<pcr0_hash_from_step_2>
export RPC_URL=https://galleon-testnet.kaskad.io

# Deploy (uses Foundry)
cd contracts
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --broadcast \
  --private-key $DEPLOYER_KEY \
  --sig "run()" \
  -vvvv
```

## 6. Register Enclave On-Chain

The enclave generates an attestation document and submits it to the contract.
This happens automatically when the oracle starts — the first thing it does is:

1. Generate a keypair inside the enclave
2. Request attestation from the Nitro Secure Module (NSM)
3. Submit `registerEnclave(attestationDoc)` via the VSOCK proxy
4. Start the price feed loop

## Architecture

```
┌────────────── EC2 Instance ──────────────────────┐
│                                                   │
│  ┌──── Nitro Enclave (CID 16) ────────────┐     │
│  │                                         │     │
│  │  kaskad-oracle binary                   │     │
│  │  ├── fetch prices (via VSOCK)           │     │
│  │  ├── aggregate (weighted median)        │     │
│  │  ├── sign (key generated inside)        │     │
│  │  └── submit TX (via VSOCK)              │     │
│  │                                         │     │
│  │  Memory: encrypted by CPU               │     │
│  │  Network: NONE (VSOCK only)             │     │
│  │  Disk: NONE (read-only rootfs)          │     │
│  │  SSH: NONE                              │     │
│  │                                         │     │
│  └────────────┬────────────────────────────┘     │
│               │ AF_VSOCK port 5000               │
│  ┌────────────▼────────────────────────────┐     │
│  │  vsock_proxy.py                         │     │
│  │  ├── whitelist: api.binance.com, ...    │     │
│  │  ├── forwards HTTP requests             │     │
│  │  └── forwards RPC to Galleon node       │     │
│  └─────────────────────────────────────────┘     │
│                                                   │
└───────────────────────────────────────────────────┘
```

## Reproducible Build Verification

Anyone can verify that the oracle running inside the enclave matches the source code:

```bash
# 1. Clone the repo
git clone https://github.com/Kaskad-Lending/kaskad-nuntius.git
cd kaskad-nuntius

# 2. Build the Docker image
docker build -t kaskad-oracle:verify .

# 3. Build the EIF (produces PCR0)
nitro-cli build-enclave \
  --docker-uri kaskad-oracle:verify \
  --output-file verify.eif

# 4. Compare PCR0 with what's registered on-chain
cast call $ORACLE_ADDRESS "expectedPCR0()(bytes32)" --rpc-url $RPC_URL

# If PCR0 matches → the on-chain oracle is running exactly this code.
# If PCR0 doesn't match → something was modified.
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `nitro-cli` not found | Install `aws-nitro-enclaves-cli` |
| Enclave fails to start | Check allocator config, ensure enough memory/CPU |
| VSOCK connection refused | Verify proxy is running, correct CID/port |
| Attestation fails on-chain | Check PCR0 matches `expectedPCR0` in contract |
| No prices fetched | Check proxy whitelist, verify CEX API endpoints |
