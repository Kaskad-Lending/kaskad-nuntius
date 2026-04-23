# Kaskad Oracle Collective Pre-Mainnet Audit (2026-04-22)

## Scope

- `Kaskad-Lending/kaskad-nuntius` (TEE/infra + pull API + relayer/backend)
- `Kaskad-Lending/kaskad-nuntius-contracts` (on-chain EVM oracle + router)

## Executive verdict

**Not mainnet-ready yet.**
Two **CRITICAL** on-chain issues remain, plus availability hardening gaps in infra/backend.

---

## Findings

## [CRITICAL] Signature replay across deployments/chains

**Category:** Smart Contract / Oracle Integrity  
**Location:** `kaskad-nuntius-contracts/src/KaskadPriceOracle.sol:273-276`, `kaskad-nuntius/src/signer.rs:29-35`  
**Impact:** A valid signed update can be replayed on another deployment/chain if signer/schema are shared.  
**Evidence:** Message hash omits domain fields (`chainId`, `verifyingContract`). Contract verifies only `keccak256(assetId,price,timestamp,numSources,sourcesHash)`.  
**Remediation:** Move to EIP-712 with explicit domain (`name/version/chainId/verifyingContract`) or prepend fixed domain bytes including chain + contract.

## [CRITICAL] Future timestamp can freeze asset feed

**Category:** Smart Contract / Availability  
**Location:** `kaskad-nuntius-contracts/src/KaskadPriceOracle.sol:237-239`  
**Impact:** One accepted far-future signed timestamp blocks all later normal updates (`timestamp <= current.signedTimestamp`), effectively freezing asset updates for long periods.  
**Evidence:** No upper-bound/future-skew guard before monotonic timestamp check.  
**Remediation:** Enforce `timestamp <= block.timestamp + MAX_FUTURE_SKEW` (e.g., 60-300s) and add governance emergency unfreeze path with strict controls.

## [HIGH] Pull API rate limit identity collapses behind ALB

**Category:** Infra/AppSec Availability  
**Location:** `kaskad-nuntius/enclave/pull_api.py:131`, `:180`, `infra/alb.tf:121-129`  
**Impact:** Limiter keys on socket peer (`client_address`), which behind ALB can collapse many users into shared buckets, enabling low-cost global throttling/DoS.  
**Remediation:** Trust and parse `X-Forwarded-For` only from ALB, apply per-client and per-path limits, and add WAF rate-based controls.

## [HIGH] Pull API is single-threaded (HoL blocking)

**Category:** Availability / DoS  
**Location:** `kaskad-nuntius/enclave/pull_api.py:194`  
**Impact:** Slow VSOCK/backend calls can head-of-line block all requests, degrading permissionless on-demand freshness flow.  
**Remediation:** Replace `HTTPServer` with threaded/async server, add strict timeouts, connection caps, and queue backpressure.

## [HIGH] EIF boot path lacks strong immutable integrity pin before run

**Category:** TEE Supply Chain / Deployment Integrity  
**Location:** `kaskad-nuntius/infra/user-data-prod.sh:65-66`, `:211-214`  
**Impact:** Instance pulls `latest.eif` from S3 and runs it without local immutable digest gate; attestation mismatch may halt updates/liveness or allow unsafe rollout mistakes.  
**Remediation:** Pin and verify SHA-384 digest/PCR set before `run-enclave`; fail closed if mismatch; require signed release manifest.

## [MEDIUM] Attestation policy appears optional in bootstrap path

**Category:** TEE Hardening  
**Location:** `kaskad-nuntius/infra/user-data-prod.sh:66`  
**Impact:** `pcr0.json` fetch is optional (`|| true`), increasing risk of accidental weak/partial attestation gating in operations.  
**Remediation:** Remove best-effort behavior; require attestation policy artifacts and fail deployment when absent.

## [MEDIUM] CONNECT proxy has no destination allowlist

**Category:** Network Egress Control  
**Location:** `kaskad-nuntius/infra/user-data-prod.sh:112-119`, `:174`  
**Impact:** Proxy bridges enclave egress to arbitrary host:port, expanding abuse surface if enclave/request path is compromised.  
**Remediation:** Enforce explicit destination allowlist (exchanges + required APIs), DNS pinning, and egress firewall rules.

## [LOW] HTTP listener forwards plaintext instead of redirecting to HTTPS

**Category:** Transport Security  
**Location:** `kaskad-nuntius/infra/alb.tf:120-129`  
**Impact:** Allows plaintext access path; increases downgrade/availability manipulation risk.  
**Remediation:** Make port 80 listener issue 301 redirect to HTTPS (or disable 80 in prod).

---

## Mainnet gate (must-fix before launch)

- [ ] **Fix CRITICAL replay:** add domain separation to signed payload verification.
- [ ] **Fix CRITICAL freeze:** add future timestamp cap + emergency recovery path.
- [ ] **Fix HIGH pull API DoS #1:** client identity + WAF/rate controls behind ALB.
- [ ] **Fix HIGH pull API DoS #2:** threaded/async API server with bounded resources.
- [ ] **Fix HIGH deployment integrity:** immutable EIF digest/PCR verification pre-launch.
- [ ] Add hard fail for attestation policy artifact loading.
- [ ] Add egress allowlist for CONNECT/VSOCK bridge.

## Validation run

- `forge test` on `kaskad-nuntius-contracts`: **56/56 passing** (includes security regression/POC suite).
- Backend security report generated at: `/root/.openclaw/agents/secops/workspace/reports/kaskad-nuntius-backend-audit.md`.

---

If needed, I can now prepare patch PRs in priority order: **(1) replay domain separation, (2) future timestamp cap, (3) pull API concurrency + rate-limit identity fix.**
