Sources of findings addressed:

- `EXPLOIT-3` from third-party "DAN coverage gap" audit (volume nullification).
- `collective_audit.md` — 8 findings C1–C8.
- A handful of incidental cleanups noticed along the way.

---

## EXPLOIT-3 — Volume nullification → equal-weight fallback

**[#24](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/24)
`feat(aggregator): strict volume parse + weighting-mode reporting + fail-closed policy`**

Three layers, none breaking sources that don't expose volume by design.

1. **Strict volume parse.** Seven sources (`gateio`, `bitstamp`, `okx`,
   `bitget`, `bybit`, `kucoin`, `kraken`) replaced `unwrap_or(0.0)` with
   `?` error propagation. A missing or malformed `volume` field now
   drops the sample for that cycle instead of silently becoming
   zero-volume. Sources without a volume field in their endpoint schema
   (`binance`, `coinbase`, `coingecko`, `mexc`, `igralabs`) are
   untouched — they keep reporting `volume: 0.0` by design.
2. **`WeightingMode` enum + alert metric.** `weighted_median` now
   returns `Option<(f64, WeightingMode)>`. A monotonic
   `EQUAL_WEIGHT_FALLBACK_COUNT` atomic increments on each fallback
   event. Pull-API `/health` exposes it as `equal_weight_fallbacks` —
   monitor polls and pages on a climb without parsing console logs.
3. **Per-asset `require_volume_weight` policy.** New `AssetConfig`
   field (serde default `false`). Pipeline refuses to publish a cycle
   for an asset with the flag set when the aggregator fell back to
   equal weighting. Enabled for `ETH/USD` and `BTC/USD` in
   `config/assets.json`.

**Deploy note.** This change touches `config/assets.json` which is baked
into the EIF via `include_str!`, so PCR0 shifts on the next CI build.
The 2026-04-27 redeploy carried this through: new EIF, new oracle
contract, Aave wiring flipped.

---

## collective_audit.md C2 — Future timestamp freeze

**[#25](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/25)
`chore(contracts): bump submodule — 2h future-timestamp cap`** + split-repo
**[kaskad-nuntius-contracts#3](https://github.com/Kaskad-Lending/kaskad-nuntius-contracts/pull/3)**.

Reintroduces the future-timestamp guard removed earlier as
"redundant with server_time", now sized for Kasplex L2 clock
volatility. `MAX_FUTURE_SKEW = 2 hours`. Reverts with
`FutureTimestamp(provided, maxAllowed)` if the signed timestamp
runs > 2h ahead of `block.timestamp`.

Cap widens with `block.timestamp` — chain-forward jumps don't false-fire.
Chain-backward beyond 2h does revert (rare).

Tests: 3 new REGRESSION tests in `SecurityAudit.t.sol`. Existing +1h /
+5min tests still pass.

**Deploy note.** Contract change. Redeployed on 2026-04-27.

---

## collective_audit.md C3 — Pull API rate-limit identity behind ALB

**[#33](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/33)
`feat(pull_api): real client IP via X-Forwarded-For when peer is ALB`**

`get_client_ip(handler)`:

- Trusts `X-Forwarded-For` only when the TCP peer is in `VPC_CIDR`
  (i.e. our ALB).
- Direct connections from outside VPC (dev / mis-routed) — peer IS
  the client; ignore XFF.
- AWS ALB chains XFF as `client, proxy1, proxy2`; first entry is the
  real client.
- Malformed / missing XFF, or non-IP peer, falls back to peer.

Wiring: systemd unit gets `Environment=VPC_CIDR=...` substituted by
terraform from `var.vpc_cidr`.

Tests: 8 unit tests in `enclave/test_pull_api.py`.

Host SG ([infra/network.tf:49-55](../infra/network.tf#L49-L55)) already
restricts :8080 to the ALB SG only — there is no spoof window.

---

## collective_audit.md C4 — Pull API single-threaded HoL blocking

**[#26](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/26)
`feat(pull_api): ThreadingHTTPServer + concurrency cap`**

- `HTTPServer` → `ThreadingHTTPServer` (stdlib drop-in).
- `Semaphore(MAX_CONCURRENT=64)` non-blocking acquire — overflow returns
  503 instead of growing the thread pool unbounded.
- `daemon_threads = True` so shutdown isn't held by a handler stuck on
  a slow VSOCK call.
- Handler body refactored into inner `_handle_get` so acquire/release
  wrap the outer `do_GET`.

**Side effect (not regression):** the host can now hit the enclave's
VSOCK 64 in flight at once. The enclave-side `spawn_blocking` was
itself unbounded — closed in PR #44 (round-2 R-1) with a matching
`Semaphore(64)` on the enclave loop.

---

## collective_audit.md C5 + C6 — EIF integrity pin (4-PR rollout)

**Step 1/4: KMS key**
[#29](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/29)
`feat(infra): KMS release-signing key for EIF integrity pin`.
ECC_NIST_P384 / ECDSA_SHA_384 asymmetric KMS key + alias
`alias/kaskad-oracle-release`. IAM grants:

- builder EC2: `kms:Sign` + `kms:GetPublicKey`.
- prod EC2: `kms:GetPublicKey` only (verify is local openssl).
- github-ci OIDC: `kms:Sign` reserved for future signing-from-runner.

**Step 2/4: CI signing**
[#30](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/30)
`feat(ci): sign EIF SHA-384 + PCR0 with KMS, upload manifests`.
Builder produces 5 artefacts per build: `latest.eif`,
`latest.eif.sha384`, `latest.eif.sha384.sig`, `pcr0.json`,
`pcr0.json.sig`.

**Step 3/4: prod verify in migration mode**
[#31](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/31)
`feat(infra): EIF integrity verification in migration mode`.
At boot, prod host fetches release pubkey from KMS once, verifies
signatures, recomputes EIF SHA-384, and checks `nitro-cli describe-eif`
PCR0 against signed `pcr0.json`. If sig artefacts are missing in S3
(early in rollout), warns + boots unverified (`MIGRATION_MODE=1`).

**Step 4/4: drop migration fallback**
[#32](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/32)
`feat(infra): drop EIF migration-mode fallback, mandatory verify`.
`set -euo pipefail` + plain `aws s3 cp` calls — any missing artefact
fails the boot, ASG marks instance unhealthy, replaces.

**Apply order is critical** — see "Apply roadmap" below.

---

## collective_audit.md C7 — CONNECT proxy destination allowlist

**[#27](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/27)
`feat(http): enclave-side exchange hostname allowlist`**

Implemented inside the enclave (per operator preference — "через Rust
выдирать ссылки") rather than at the host-side CONNECT proxy:

- `config/assets.json`: top-level `exchange_hostnames` (15 entries).
- `AssetsConfig` parses it; `load_assets` rejects empty / malformed.
- `HttpClient::new(enclave_mode, allowed_hosts)` stores the list.
- `get_json_with_time` parses the URL, rejects disallowed hosts before
  any connection.
- Drift-guard test pins (source_name → hostname) mapping. Adding a new
  exchange requires editing both `EXPECTED` and the config.

**Deploy note.** `config/assets.json` change → PCR0 shift. Carried
through the 2026-04-27 redeploy.

---

## collective_audit.md C8 — HTTP listener forwards plaintext

**[#34](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/34)
`feat(infra): conditional HTTPS + 301 redirect when domain attached`**

Code-only — operator action required:

- HTTP listener split into two `count`-gated resources. With
  `var.domain_name` set: `http_redirect[0]` issues 301 → HTTPS:443.
  Without: `http_forward[0]` keeps current passthrough.
- Two new outputs for external DNS bootstrap:
  `acm_dns_validation_records` (CNAMEs to add at registrar),
  `domain_cname_target` (ALB DNS to point domain at).

Operator workflow detailed in PR #34 description (Namecheap CNAME steps).

---

## Skipped — explicitly decided not to fix

Three findings were closed by **decision**, not code, with operator
sign-off after detailed analysis. None of them describe a current
attack surface in the deployed product.

### collective_audit.md C1 — Signature replay across deployments/chains

`updatePrice` payload omits `chainId` / `verifyingContract` /
nonce; signature is bound only to `(assetId, price, timestamp,
numSources, sourcesHash)`.

**Why skipped.** Consumers select an oracle by deployed contract
address, not by PCR0 / signer. A shadow `KaskadPriceOracle` deployed
by an attacker on another chain (or another address) is irrelevant
to any consumer that uses the documented production address. The
attacker's "shadow" is only meaningful if a consumer is misconfigured
to point at it — that is the consumer's bug, not ours.

Cross-chain replay only becomes a real concern if WE deploy on multiple
chains via CREATE2 with the same address AND a consumer trusts the
address blindly without checking origin chain — not currently planned.

EIP-712 domain separator is cheap insurance for hypothetical
multi-chain deploys, ~40 gas/update, but not a current vulnerability.
Reopen when a multi-chain plan exists.

### Round-3 audit H-3 — `KaskadStalenessChecker._checkAllAssets` unbounded iteration

Sentinel iterates over every Aave reserve when `router.sender() == 0`
(direct Pool call), one external `latestRoundData()` call per reserve.
Auditor flagged "10+ assets → gas DoS preventing liquidations".

**Why skipped.** Aave v3 hard-caps reserves at 128
(`MAX_NUMBER_RESERVES`), real deployments run 15-25. Worst case 128 ×
≈10k gas = 1.28 M — within block gas limit, not a hard DoS. Sentinel
returning `false` on stale prices is correct behaviour, not a denial of
service. Liquidators routing through `KaskadRouter` hit
`_checkUserAssets` (only the user's positions, ≤5 reserves typically)
which is cheap. Auditor's proposed fixes ("cap iteration" or "force
all interactions through Router") are either lossy (returning false at
cap removes the staleness check) or unenforceable (Aave Pool is
permissionless, can't deny direct calls).

A better fix exists — asymmetric fallback (`isLiquidationAllowed`
returns `true` on direct-Pool to keep clearing bad debt;
`isBorrowAllowed` returns `false` to push borrows through Router) —
but that's a redesign, not the auditor's recommendation, and not
actionable in this session.

### Round-3 audit M-4 — `debtToCover = 0` griefing

Auditor: zero-value `liquidateWithPrices` "passes router validation but
reverts in Aave, wasting gas and price update slots".

**Why skipped.** Verified against the actual Aave v3 source
(`LiquidationLogic.executeLiquidationCall` / `validateLiquidationCall`):
**Aave does not revert** on `debtToCover == 0`. The
`actualDebtToLiquidate` collapses to 0, transfers are no-op, the call
silently succeeds. The "wasting gas" claim is true but the gas is the
attacker's own (their tx, their wallet) — no griefing of others. The
"wasting price update slots" claim conflates `_pushPrices` semantics:
attacker-funded price relays actually help the protocol (free
keeper-style propagation), and `currentRound` is `uint80`, effectively
inexhaustible.

A `require(debtToCover > 0)` would be cheap hygiene but is not a
security fix — it just relocates the no-op revert from Aave's silent
path into the Router's explicit one. Skipped.

### EXPLOIT-3 alternative — "tighter MAD sigma in fallback mode"

This was the auditor's mitigation #1 for the volume-nullification
finding. Argument: when equal-weight fallback fires, lower the MAD
sigma to compensate.

**Why skipped.** Backwards. If an attacker has nullified volume on
≥50% of sources (precondition for the fallback firing), they
necessarily control ≥50% of the surviving samples. A tighter MAD then
rejects MORE samples — which means rejecting the HONEST minority,
leaving only the attacker-controlled majority. Mitigation made
exploitation easier.

Replaced with the inverse approach (#24): `require_volume_weight = true`
on critical assets refuses to publish in fallback mode, fail-closed. A
tighter MAD is never the right answer here.

---

## Cleanups (not finding-driven)

- **[#23](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/23)**
  `chore: drop unused publisher module` — removed 316-line orphan
  `src/publisher.rs` (no `mod publisher;` anywhere; pull-based design
  routes on-chain submission through the TS relayer).
- **[#28](https://github.com/Kaskad-Lending/kaskad-nuntius/pull/28)**
  `chore: drop collective_audit.md` — file landed in #27 via
  `git add -A`, removed.

## Split repo (`kaskad-nuntius-contracts`) cleanups

- **[contracts#1](https://github.com/Kaskad-Lending/kaskad-nuntius-contracts/pull/1)**
  `chore(deps): pin forge-std as submodule at v1.15.0` — was a plain
  vendored tree; converted to a proper submodule pinned at v1.15.0
  (byte-identical to the previous copy).
- **[contracts#2](https://github.com/Kaskad-Lending/kaskad-nuntius-contracts/pull/2)**
  `chore: apply Apache-2.0 license` — added LICENSE.

---

## Apply history

All operator steps below were executed on **2026-04-27**:

1. `terraform apply` — KMS key, ALB listener split, ASG launch template (`#29 / #34 / #45`).
2. `gh workflow run deploy.yml` — built new EIF, signed via KMS, uploaded 5 manifests to S3.
3. `terraform apply` — second wave: user-data verify in mandatory mode (`#31 / #32` collapsed since manifests already present).
4. ASG instance refresh completed — new enclave running, signer `0xa41623b35a16751d7433d5d7bb93ebdb2b6e5fa2`, PCR0 `5b1de8e90cc54ce369bc35add62dc12b68df3860cab8e73b11866879ca3bbdd3dfb2e62c95021af292c1bd9ba05ae192`, `EIF integrity verified` confirmed in `/kaskad/oracle` CloudWatch.
5. Galleon contract redeploy via `forge script DeployLocal.s.sol --broadcast` (real Nitro stack still blocked by Galleon's ~3.5 h block.timestamp drift). New addresses in [contracts/deployments/galleon.json](../contracts/deployments/galleon.json).
6. `AaveOracle.setAssetSources` flipped WETH/WBTC/USDC/WIKAS to the new aggregators — tx `0x8472d0f7…`.
7. `oracle.kaskad.live` attached: ACM cert issued, HTTPS listener active, port 80 → 301 → 443.

`AaveOracle.getAssetPrice` returns live signed prices; pull API at `https://oracle.kaskad.live` healthy.

---

## Round-2 multi-agent audit follow-up

A second remediation pass addressed most of the round-2 findings. Status:

### Closed in code (this session)

**Contracts (kaskad-nuntius-contracts):**

- **F-13** evm_version pinned to "cancun" in `foundry.toml` — PR #5.
- **F-5** `registerAssets` capped at `MAX_ASSETS = 32` — PR #6.
- **F-6** `getRoundData` reverts with `NoRoundData` on missing round — PR #6.
- **D-2** `EXPECTED_PCR1/2 != bytes32(0)` pre-flight require in `Deploy.s.sol` — PR #5.
- **D-3** `ORACLE_ADMIN != deployer` pre-flight require — PR #5.
- **D-5** optional `EXPECTED_ENCLAVE_SIGNER` binding — PR #5.

**Rust runtime (PR #44):**

- **R-1** `spawn_blocking` wrapped in `Semaphore(64)`, overflow drops connection.
- **R-2** `get_attestation` cached 5 min (well inside 3 h leaf cert TTL).
- **R-4** `read_exact_with_deadline` enforces 15 s wall-clock budget; idle timeout no longer spans days.
- **R-6** `KASKAD_ALLOW_MOCK_SIGNER=1` opt-in required for MockSigner outside `ENCLAVE_MODE`. Test scripts updated.
- **R-8** `warn!` on handler error no longer echoes attacker-controlled bytes.
- **R-19** price server failure → `std::process::exit(1)`; systemd / ASG restart kicks in.

**Infra:**

- **S-1** Dockerfile base images digest-pinned — PR #45.

### Closed by decision (skipped after analysis)

- **F-3** Originally listed open in error — `Deploy.s.sol` already had no stale `envOr` references.
- **F-4** Audit overstates: `aToken.transferFrom + pool.withdraw` with the same `pullAmount` is atomic; `getReserveNormalizedIncome` is a view function whose value during the tx equals what `updateState` then stores. `rayDiv` / `rayMul` round identically across both ops, net scaled balance change = 0. No dust within an atomic tx. (Donations on the router are a separate concern, already covered by the M-1 delta-based refund pattern.)
- **R-7** `blocking_read` on writer-preferring `RwLock` — fix would be a switch to `arc-swap` or `parking_lot` + benchmark. Not a regression; the existing aggregator cycle holds the write lock briefly. Re-open if a real stall is observed in production.
- **R-20** `attestation_doc` returns `None` without distinguishing "NSM unavailable" vs "not initialized". UX, not security. Skip.
- **S-3** relayer `package-lock.json` — relayer is out of scope for this session per operator.
- **S-5** ephemeral builder EC2 (one fresh spot per build) — substantial infra refactor with no concrete attack vector under the current threat model. Skip.
- **S-9** apk package version pinning — would require an Alpine APK archive snapshot service to keep CI working through Alpine repo updates. Operational maintenance burden outweighs the marginal PCR0-stability gain on top of S-1's image digest. Skip.

---

## Summary

All session work — code, deploy, contract redeploy, wiring — completed on 2026-04-27.

### Closed

| Finding                                  | PR(s)                            |
| ---------------------------------------- | -------------------------------- |
| EXPLOIT-3 (volume nullification)         | #24                              |
| C2 — future-ts cap                       | #25 (+ contracts #3)             |
| C3 — pull API rate-limit identity        | #33                              |
| C4 — pull API HoL blocking               | #26                              |
| C5 + C6 — EIF integrity pin              | #29, #30, #31, #32               |
| C7 — hostname allowlist                  | #27                              |
| C8 — HTTP→HTTPS redirect + domain attach | #34, ACM cert + Namecheap CNAMEs |
| Round-2 F-5 — `registerAssets` cap       | contracts #6 (+ bump #43)        |
| Round-2 F-6 — `getRoundData` revert      | contracts #6                     |
| Round-2 F-13 — `evm_version` pin         | contracts #5                     |
| Round-2 D-2 — PCR1/2 non-zero            | contracts #5                     |
| Round-2 D-3 — admin ≠ deployer           | contracts #5                     |
| Round-2 D-5 — expected-signer binding    | contracts #5                     |
| Round-2 R-1 — `spawn_blocking` semaphore | #44                              |
| Round-2 R-2 — `get_attestation` cache    | #44                              |
| Round-2 R-4 — drip-feed deadline         | #44                              |
| Round-2 R-6 — `KASKAD_ALLOW_MOCK_SIGNER` | #44                              |
| Round-2 R-8 — error-log redact           | #44                              |
| Round-2 R-19 — abort on crash            | #44                              |
| Round-2 S-1 — Docker digest pin          | #45                              |

### Skipped

| Finding                                                 | Reason                                                                                                                                                                                                                              |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1 — signature replay across deployments/chains         | Single-chain deployment; consumers select an oracle by deployed address, not by PCR0 / signer. Attacker's shadow contract is irrelevant unless a consumer is misconfigured to trust it. Re-open when a multi-chain plan exists.     |
| Round-3 H-3 — `_checkAllAssets` unbounded iteration     | Aave v3 caps reserves at 128; worst-case 1.28 M gas, well within block limit. Sentinel returning `false` on stale prices is correct behaviour, not a DoS. Auditor's proposed fixes (cap iteration / force Router) are lossy or unenforceable. |
| Round-3 M-4 — `debtToCover = 0` griefing                | Verified Aave v3 source: `debtToCover == 0` does **not** revert, the call is a silent no-op. Wasted gas is the attacker's own. `_pushPrices` slot consumption is not exhaustible (`uint80` rounds). `require(debtToCover > 0)` would relocate the no-op revert from Aave to Router with no security gain. |
| EXPLOIT-3 alternative — "tighter MAD sigma in fallback" | Backwards. If attacker has nullified volume on ≥50 % of sources, they control ≥50 % of survivors. Tighter MAD rejects more samples — preferentially the honest minority — making the exploit easier. Replaced with `require_volume_weight = true` fail-closed policy in #24. |
| Round-2 F-3 — deploy script `envOr` references          | Listed open in error; `Deploy.s.sol` already had no stale `envOr` references at the time of audit reading.                                                                                                                          |
| Round-2 F-4 — `withdrawWithPrices` aToken dust          | Atomic-tx invariant: `aToken.transferFrom(U) + pool.withdraw(U)` netto-zero scaled balance change. `getReserveNormalizedIncome` is a view function returning the same index value `updateState` then stores; `rayDiv` / `rayMul` round identically. No dust within an atomic tx. Donations are M-1, separate. |
| Round-2 R-7 — `blocking_read` writer-preferring RwLock  | Fix = switch to `arc-swap` / `parking_lot` + benchmark. Not a regression — aggregator cycle holds the write lock briefly. Re-open if a real stall is observed in production.                                                        |
| Round-2 R-20 — `attestation_doc` returns `None`         | UX issue (no structured error code distinguishing "NSM unavailable" vs "not initialized"). Not security.                                                                                                                            |
| Round-2 S-3 — relayer `package-lock.json`               | Relayer is out of scope per operator request.                                                                                                                                                                                       |
| Round-2 S-5 — long-lived builder EC2                    | Substantial infra refactor (one fresh spot instance per build) with no concrete attack vector under the current threat model.                                                                                                       |
| Round-2 S-9 — apk package version pin                   | Would require an Alpine APK archive snapshot service to keep CI working through repo updates. Operational maintenance burden outweighs the marginal PCR0-stability gain on top of S-1's base-image digest pin.                       |
