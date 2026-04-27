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

**Apply note.** This change touches `config/assets.json` which is baked
into the EIF via `include_str!`. **PCR0 changes** with the next CI build —
contract redeploy required (see "Apply roadmap" at the bottom).

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

**Apply note.** Contract change → redeploy `KaskadPriceOracle`.

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
VSOCK 64 in flight at once. The enclave-side `spawn_blocking` is still
unbounded (round-2 audit R-1 — open) — fix planned separately.

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

**Apply note.** `config/assets.json` change → PCR0 changes → contract
redeploy.

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

## Apply roadmap (operator action)

The PRs are merged into `main` but **not yet applied to prod**. Order
matters:

1. **`terraform apply`** — applies #29 (KMS key) and #34 (listener
   split structure). No instance refresh, no ABI-breaking change.

2. **GitHub Actions → "Production Deploy" → Run workflow** —
   `workflow_dispatch` only. CI builds the EIF and produces all 5
   signed artefacts in S3 (#30 active).

3. **`terraform apply`** — applies #31 (user-data with migration-mode
   verify). ASG instance refresh; new instance boots and verifies if
   manifests are present, warns + boots if missing.

4. **Verify** in CW logs `/kaskad/oracle` → look for
   `EIF integrity verified (sha384 + PCR0 signed by release KMS key)`
   on the new instance.

5. **`terraform apply`** — applies #32 (mandatory verify; drops
   migration fallback). Second instance refresh; this one fails-closed
   if any artefact is missing.

6. **Contract redeploy.** PCR0 changes due to #24 (`exchange_hostnames`
   added to `config/assets.json`) and #27 (same file) and the contract
   constants from #25 (`MAX_FUTURE_SKEW`, `FutureTimestamp` error). All
   require new `expectedPCR0` immutable. Plan:
   - Run a fresh CI build → grab `pcr0.json` from S3.
   - `forge script DeployReal.s.sol` with `EXPECTED_PCR0=<new>`,
     `ORACLE_ADMIN`, `EXPECTED_PCR1/PCR2`.
   - `registerEnclave` from a fresh attestation.
   - `registerAssets` to bootstrap quorum.
   - Migrate Aave aggregator wiring (`AaveOracle.setAssetSources`) to
     point at the new contract.

7. **C8 attach domain** (when ready):
   - Set `domain_name = "oracle.kaskad.live"` in
     `infra/terraform.tfvars`.
   - `terraform apply`.
   - `terraform output acm_dns_validation_records` →
     copy CNAMEs into Namecheap (Advanced DNS → Add CNAME).
   - Add a second CNAME for `oracle` →
     `terraform output -raw domain_cname_target`.
   - Wait for DNS propagation + ACM auto-validation (5-30 min).
   - `terraform apply` again.
   - Test:
     `curl -I http://oracle.kaskad.live/health` → 301 to HTTPS;
     `curl https://oracle.kaskad.live/prices` → signed JSON.

---

## Findings still open (round-2 multi-agent audit)

Not addressed in this session. Reference for next round:

**Solidity (in `kaskad-nuntius-contracts`)**

- F-3 deploy script comments still reference removed `envOr` fallback.
- F-4 `withdrawWithPrices` aToken rebasing dust accumulation.
- F-5 `registerAssets` unbounded delete loop griefing.
- F-6 `KaskadAggregatorV3.getRoundData(non_existent)` returns
  `answer=0` success (Chainlink convention violation).
- F-13 `evm_version` not pinned in `foundry.toml`.

**Rust runtime**

- R-1 `tokio::spawn_blocking` unbounded in enclave price_server. (C4
  fixed the host-side analogue.)
- R-2 `get_attestation` spam starves NSM serial device.
- R-4 `vec![0u8; req_len]` drip-feed bypasses idle read_timeout.
- R-6 `ORACLE_PRIVATE_KEY` env footgun (one typo of `ENCLAVE_MODE` →
  host-controlled signing key).
- R-7 `blocking_read` writer-preferring `RwLock` stalls.
- R-8 `handle_connection` error echo into host-readable logs.
- R-19 price server crash silent (no abort).
- R-20 `attestation_doc` returns `None` without distinguishing error
  code.

**Deploy / Infra / Supply**

- D-2 explicit `EXPECTED_PCR1/2 != 0` check at script-level.
- D-3 `ORACLE_ADMIN != deployer` assertion.
- D-5 attestation-doc → expected-signer binding at deploy.
- S-1 Dockerfile base image tag-pinned (not digest-pinned).
- S-3 relayer `package-lock.json` not committed.
- S-5 builder long-lived EC2 (vs ephemeral spot-per-build).
- S-9 apk packages not pinned.

---

## Summary by category

| Category                    | Closed in code                       | Awaits operator             | Open             |
| --------------------------- | ------------------------------------ | --------------------------- | ---------------- |
| EXPLOIT-3 (volume)          | ✓ #24                                | redeploy contract (PCR0 ↻)  | –                |
| Contract: future-ts cap     | ✓ #25                                | redeploy contract           | –                |
| Pull API: rate-limit ID     | ✓ #33                                | tf apply                    | –                |
| Pull API: HoL blocking      | ✓ #26                                | tf apply                    | enclave-side R-1 |
| EIF integrity pin           | ✓ #29-32                             | 5-step apply                | –                |
| Hostname allowlist          | ✓ #27                                | redeploy contract (PCR0 ↻)  | –                |
| HTTP→HTTPS redirect         | ✓ #34                                | domain attach via Namecheap | –                |
| Replay (C1)                 | rejected by design                   | –                           | –                |
| Sentinel iteration (H-3)    | rejected — Aave caps reserves        | –                           | –                |
| `debtToCover = 0` (M-4)     | rejected — Aave is no-op, not revert | –                           | –                |
| EXPLOIT-3 alt (tighter MAD) | rejected — counterproductive         | –                           | –                |
| Round-2 multi-agent         | partial                              | –                           | ~20 findings     |
