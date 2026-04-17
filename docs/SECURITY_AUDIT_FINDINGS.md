# Kaskad TEE Oracle — Security Audit Findings

**Scope:** Rust oracle (`src/`), Solidity contracts (`contracts/src/`), TypeScript relayer (`relayer/src/`), Docker/EIF build, Galleon deployment config.
**Method:** whitebox review + proof-of-concept tests. Every factual claim cites file:line. Every finding has a runnable reproduction.
**Reproduction:**
- `cd contracts && forge test --match-contract SecurityAuditTest -vvv` → 7 PoC pass
- `cargo test --test security_audit` → 11 PoC pass

---

## Severity scale

| Level | Definition |
|---|---|
| **CRITICAL** | Loss of funds, permanent freeze, or complete bypass of TEE trust assumption. |
| **HIGH** | Practical exploit that requires only a plausible precondition (compromised CEX, enclave bug, operational mistake). |
| **MEDIUM** | Exploit requires an unusual state or multiple steps; defence-in-depth gap. |
| **LOW / INFO** | Deviation from best practice with no immediate exploit. |

---

## Summary table

| ID | Sev | Title | Primary evidence | PoC |
|---|---|---|---|---|
| [C-1](#c-1) | CRIT | Galleon production deploy has **no TEE trust** (MockVerifier + EOA signer) | [deployments/galleon.json:8-15](../contracts/deployments/galleon.json#L8-L15), [script/DeployGalleon.s.sol:34-42](../contracts/script/DeployGalleon.s.sol#L34-L42) | trivial |
| [C-2](#c-2) | CRIT | Signature replay across contract deployments (no chainId / no verifyingContract) | [signer.rs:82-87](../src/signer.rs#L82-L87), [KaskadPriceOracle.sol:180-185](../contracts/src/KaskadPriceOracle.sol#L180-L185) | `test_POC_signature_replay_across_deployments` |
| [C-3](#c-3) | CRIT | Permanent price freeze via far-future `signedTimestamp` | [KaskadPriceOracle.sol:159-162](../contracts/src/KaskadPriceOracle.sol#L159-L162) | `test_POC_future_timestamp_freezes_asset_permanently` |
| [C-4](#c-4) | CRIT | NaN price → on-chain price = 0 | [aggregator/mod.rs:33,80-83](../src/aggregator/mod.rs#L33) | `POC_nan_price_becomes_zero_fixed_point`, `POC_nan_not_rejected_by_aggregator` |
| [C-5](#c-5) | CRIT | Self-reported volume controls weighted median | [aggregator/mod.rs:38-47](../src/aggregator/mod.rs#L38-L47), [sources/kucoin.rs:65](../src/sources/kucoin.rs#L65), [sources/htx.rs:42](../src/sources/htx.rs#L42) | `POC_one_source_with_huge_volume_wins_median` |
| [H-1](#h-1) | HIGH | `maxAttestationAge = 365 days` + permissionless re-register | [DeployGalleonReal.s.sol:30](../contracts/script/DeployGalleonReal.s.sol#L30) | flagged |
| [H-2](#h-2) | HIGH | Per-asset min-sources quorum NOT enforced on-chain | [KaskadPriceOracle.sol:154-155](../contracts/src/KaskadPriceOracle.sol#L154-L155), [types.rs:82-89](../src/types.rs#L82-L89) | `test_POC_per_asset_min_sources_not_enforced_onchain` |
| [H-3](#h-3) | HIGH | Rate limiter & future-ts cap claimed in docs but NOT implemented | [CLAUDE.md](../CLAUDE.md) vs [KaskadPriceOracle.sol:143-207](../contracts/src/KaskadPriceOracle.sol#L143-L207) | `test_POC_no_rate_limiter_sub_5s_updates_accepted`, `test_POC_no_future_timestamp_cap` |
| [H-4](#h-4) | HIGH | Circuit-breaker bypass after 4 h lets enclave push any price | [KaskadPriceOracle.sol:167-177](../contracts/src/KaskadPriceOracle.sol#L167-L177) | `test_POC_circuit_breaker_bypass_after_4h_allows_1000x` |
| [H-5](#h-5) | HIGH | IGRA governance price from unattested runtime env var | [main.rs:169-172](../src/main.rs#L169-L172), [types.rs:85-99](../src/types.rs#L85-L99), [DeployGalleonReal.s.sol:33-34](../contracts/script/DeployGalleonReal.s.sol#L33-L34) | flagged |
| [H-6](#h-6) | HIGH | 3-of-N colluding sources bypass MAD outlier rejection and shift median | [aggregator/mod.rs:52-76](../src/aggregator/mod.rs#L52-L76) | `POC_mad_collusion_shifts_median` |
| [H-7](#h-7) | HIGH | `expectedPCR1/PCR2 = bytes32(0)` skips kernel/app measurement forever | [NitroAttestationVerifier.sol:78-79](../contracts/src/NitroAttestationVerifier.sol#L78-L79), [DeployGalleonReal.s.sol:33-34](../contracts/script/DeployGalleonReal.s.sol#L33-L34) | flagged |
| [H-8](#h-8) | HIGH | HTTP response size unbounded — OOM crashes enclave | [http_client.rs:40](../src/http_client.rs#L40) | flagged |
| [H-9](#h-9) | HIGH | Host-controlled clock flows into on-demand signatures | [price_server.rs:121](../src/price_server.rs#L121), [main.rs:44-48](../src/main.rs#L44-L48), [types.rs:13-15](../src/types.rs#L13-L15) | `POC_heartbeat_underflow_on_clock_rewind` |
| [M-1](#m-1) | MED | Router sweeps any pre-existing token balance to caller | [KaskadRouter.sol:201-210](../contracts/src/KaskadRouter.sol#L201-L210) | `test_POC_router_sweeps_donated_tokens_on_liquidate` |
| [M-2](#m-2) | MED | `to_fixed_point` saturates instead of rejecting on overflow | [aggregator/mod.rs:80-83](../src/aggregator/mod.rs#L80-L83) | `POC_fixed_point_saturates_on_overflow`, `POC_infinity_price_becomes_u128_max` |
| [M-3](#m-3) | MED | TxQueue marks reverted Tx as "confirmed" (no `receipt.status` check) | [relayer/src/tx-queue.ts:79-89](../relayer/src/tx-queue.ts#L79-L89) | flagged |
| [M-4](#m-4) | MED | Enclave-signer cache never refreshed — blind to rotation | [relayer/src/relay.ts:29,46-54](../relayer/src/relay.ts#L29) | flagged |
| [M-5](#m-5) | MED | Non-positive volume from ≥ half sources disables weighting silently | [aggregator/mod.rs:17-27](../src/aggregator/mod.rs#L17-L27) | `POC_non_positive_volume_flips_volume_weighting_off` |
| [M-6](#m-6) | MED | 14-of-14 sources bound only by URL (Bitfinex + Bitstamp have no pair ID in payload) | [sources/bitfinex.rs:41-69](../src/sources/bitfinex.rs#L41-L69), [sources/bitstamp.rs](../src/sources/bitstamp.rs) | flagged |
| [M-7](#m-7) | MED | Attestation request uses no nonce → attestation doc can be replayed within `maxAttestationAge` | [signer.rs:166-170](../src/signer.rs#L166-L170) | flagged |
| [M-8](#m-8) | MED | PCR-0 truncated from 48 → 32 bytes (SHA-384 → SHA-256 margin) | [NitroAttestationVerifier.sol:105-109](../contracts/src/NitroAttestationVerifier.sol#L105-L109) | flagged |
| [L-1](#l-1) | LOW | Dead `run_vsock_tcp_bridge` function | [main.rs:319-340](../src/main.rs#L319-L340) | flagged |
| [L-2](#l-2) | LOW | Even-count median in outlier rejection picks upper middle | [aggregator/mod.rs:60](../src/aggregator/mod.rs#L60) | `POC_reject_outliers_even_count_upper_bias` |
| [L-3](#l-3) | LOW | `sources_hash` mixes big-endian keccak with little-endian f64 bytes | [aggregator/mod.rs:87-96](../src/aggregator/mod.rs#L87-L96) | flagged |
| [L-4](#l-4) | LOW | No `max_redirects`, no body size limit, no per-stage HTTP timeouts | [http_client.rs:17-33](../src/http_client.rs#L17-L33) | flagged |

Total: **5 critical, 9 high, 8 medium, 4 low** = 26 findings.

---

## Critical findings

### C-1 — Production deploy on Galleon has no TEE trust

**Evidence.** [deployments/galleon.json](../contracts/deployments/galleon.json):

```json
"MockAttestationVerifier": "0xC1a59463E4d00dc08F146adF80E18DB807266DF1",
"expectedPCR0": "0x0000000000000000000000000000000000000000000000000000000000000001",
"enclaveSigner":  "0x931acf64D84f743B598F1c1deDb0ABfC3f3Ea2A3"
```

[DeployGalleon.s.sol:34-42](../contracts/script/DeployGalleon.s.sol#L34-L42) instantiates `MockAttestationVerifier` — `verifyAttestation` accepts ANY bytes and returns a pre-configured signer ([mocks/MockVerifiers.sol:19-26](../contracts/test/mocks/MockVerifiers.sol#L19-L26)). `expectedPCR0 = 0x…01` is garbage — not a real enclave measurement.

**Impact.** There is no TEE guarantee on Galleon right now. Whoever holds the private key for `0x931acf…2A3` has complete authority over `updatePrice` for every asset. A compromised (or malicious) operator can sign any price — there is nothing TEE-backed about it, despite the on-chain contract advertising "Only code with the correct PCR0 hash can become the oracle signer" ([KaskadPriceOracle.sol:9](../contracts/src/KaskadPriceOracle.sol#L9)).

The `_note` in `galleon.json` acknowledges this as a Galleon-block-timestamp / Marlin-NitroProver blocker, matching the `project_nitro_verifier_blocker.md` memory. However, the deployment remains LIVE, integrates with Aave V3 via 4 aggregators, and is reachable by protocol consumers.

**Fix.** Do NOT promote to mainnet until NitroAttestationVerifier is actually usable. If Galleon must host something in the interim, add a public banner in the contract (e.g. `bool public constant IS_TEE_SECURED = false;`) so integrators know the trust model.

---

### C-2 — Signature replay across deployments (no chainId / no domain separator)

**Evidence.** The signed payload is:

```rust
// src/signer.rs:82-87
payload.extend_from_slice(asset_id.as_slice());                 // 32 B
payload.extend_from_slice(&price.to_be_bytes::<32>());          // 32 B
payload.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>()); // 32 B
payload.extend_from_slice(&[num_sources]);                      // 1 B
payload.extend_from_slice(sources_hash.as_slice());             // 32 B
```

Matching verification at [KaskadPriceOracle.sol:180-185](../contracts/src/KaskadPriceOracle.sol#L180-L185). **No chainId. No verifyingContract. No EIP-712 domain separator.**

**PoC.** `test_POC_signature_replay_across_deployments` deploys two KaskadPriceOracle instances, registers the SAME enclave signer on both (legitimate per design — anyone with a valid attestation can register), and replays a single signature on both contracts — accepted by both.

```
[PASS] test_POC_signature_replay_across_deployments() (gas: 1656275)
```

**Impact.** If the oracle ever ships on more than one chain (mainnet + L2, testnet + mainnet, or a re-deployed version after a bug), every signature created by the enclave is valid on every deployment. An attacker can split liveness: feed fresh signatures to one deployment, withhold them on another, and permanently skew prices between them. The "permissionless" re-registration design amplifies this — any third party can stand up a KaskadPriceOracle with the same signer and drain users who trust it.

**Fix.** Bind the payload to `(chainId, address(this))`. Standard practice is EIP-712:

```solidity
bytes32 DOMAIN = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("KaskadOracle"), keccak256("1"), block.chainid, address(this)
));
```

Rust side: `payload = keccak256(DOMAIN) || assetId || price || …` with DOMAIN provided per-deployment (set at construction, read on-chain by the enclave via VSOCK → host query, or hard-coded per Docker image).

---

### C-3 — Permanent price freeze via far-future `signedTimestamp`

**Evidence.** [KaskadPriceOracle.sol:159-162](../contracts/src/KaskadPriceOracle.sol#L159-L162):

```solidity
if (current.signedTimestamp > 0 && timestamp <= current.signedTimestamp) {
    revert StalePrice(timestamp, current.signedTimestamp);
}
```

Every subsequent `updatePrice` must have a strictly greater `signedTimestamp`. If ONE update lands with `ts = 2100-01-01`, every legit update is locked out for 74 years. The CIRCUIT_BREAKER_STALENESS bypass at [line 167](../contracts/src/KaskadPriceOracle.sol#L167) is on a DIFFERENT field (`block.timestamp - current.timestamp`) and only skips the 15 % change check — it does nothing for the stale-ordering check above.

The timestamp comes from the enclave, specifically [price_server.rs:121](../src/price_server.rs#L121):

```rust
let timestamp = now_secs();
```

`now_secs()` is `SystemTime::now()` — the guest kernel clock, controllable by the host within well-understood bounds (KVM clock injection, vCPU time ADI). The comment at [types.rs:13-15](../src/types.rs#L13-L15) says `server_time` is the "trusted clock source inside the enclave since the host controls the system clock" — but the code never uses `server_time`. It uses `SystemTime::now()` everywhere: aggregation ([main.rs:44](../src/main.rs#L44)), per-source timestamps ([sources/*.rs](../src/sources/)), and the signing timestamp above.

**PoC.** `test_POC_future_timestamp_freezes_asset_permanently` accepts a timestamp = 2100-01-01 and then shows that all subsequent real-time updates revert with `StalePrice`, even after 30 days.

**Impact.** A single errant signature (bug, clock skew, compromised signing path) permanently freezes the asset. Recovery requires redeploying the oracle — which breaks all integrations that have hard-coded the aggregator addresses into Aave config.

**Fix.**
1. Cap `timestamp` at `block.timestamp + MAX_FUTURE_SKEW` (the 5-minute cap claimed in CLAUDE.md but never implemented, see H-3). Revert on `timestamp > block.timestamp + 5 minutes`.
2. Use `server_time` (exchange-reported) inside the enclave instead of SystemTime::now(). Take a defensive median across all source `server_time`s to tolerate one rogue CEX.

---

### C-4 — NaN price is silently signed as 0

**Evidence.**
- [aggregator/mod.rs:33](../src/aggregator/mod.rs#L33): `weighted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));` — NaN compares to everything as `Equal`, sort is stable → NaN is retained rather than rejected.
- [aggregator/mod.rs:80-83](../src/aggregator/mod.rs#L80-L83): `(price * multiplier).round() as u128` — Rust's saturating float→int cast maps `NaN` to `0`.
- 13 of 14 sources pass raw `f64::parse()` results through without an `is_finite()` check. Example [sources/kucoin.rs:64](../src/sources/kucoin.rs#L64): `let price: f64 = resp.data.price.parse()?;`. Only [sources/bitfinex.rs:54-60](../src/sources/bitfinex.rs#L54-L60) checks `is_finite() && price > 0.0`.

**PoC.**
```
test POC_nan_price_becomes_zero_fixed_point ... ok
test POC_nan_not_rejected_by_aggregator ... ok
test POC_infinity_price_becomes_u128_max ... ok
```

**Impact.** A CEX that serves `"price": "NaN"` (parses cleanly into `f64::NAN`), or any source that returns a JSON value that becomes NaN after arithmetic, can propagate NaN all the way to the signing payload. The enclave will legitimately sign `(ETH/USD, price=0, ts=now, numSources=N, sourcesHash)`. On the first-time-after-deploy or after-staleness-bypass path, the circuit breaker does not engage and 0 sticks. Every Aave lender is instantly under-collateralised → cascade of liquidations.

`f64::INFINITY` saturates to `u128::MAX` = ~3.4 × 10³⁸; converted to price-with-8-decimals that is 3.4 × 10³⁰ — equally catastrophic the other way.

**Fix.** Reject any `PricePoint` with `!price.is_finite() || price <= 0.0` at the source boundary AND in the aggregator before `to_fixed_point`. Belt-and-braces: refuse to sign if `price_fixed == 0` or `price_fixed > SANITY_MAX`.

---

### C-5 — Self-reported volume controls weighted median

**Evidence.**
- [aggregator/mod.rs:23-27](../src/aggregator/mod.rs#L23-L27): weight is `p.volume` verbatim — no normalisation, no cap, no cross-source sanity check.
- [aggregator/mod.rs:38-47](../src/aggregator/mod.rs#L38-L47): `cumulative >= half` returns the first price whose cumulative weight passes `total_weight / 2`. A source whose reported volume alone exceeds half of total weight IS the median.
- Volume comes from the source itself: `vol.parse().unwrap_or(0.0)` ([kucoin.rs:65](../src/sources/kucoin.rs#L65)), `volume24h.parse().unwrap_or(0.0)` ([bybit.rs:75](../src/sources/bybit.rs#L75)), `amount: f64` raw ([htx.rs:42](../src/sources/htx.rs#L42)), `arr[7]` raw ([bitfinex.rs:50](../src/sources/bitfinex.rs#L50)).

**PoC.** `POC_one_source_with_huge_volume_wins_median`: seven honest sources around $2000 with realistic volumes (~1k each), plus one attacker at $1998 reporting 1 × 10¹² in volume → weighted median = $1998 verbatim.

```
test POC_one_source_with_huge_volume_wins_median ... ok
```

**Impact.** The oracle advertises "14 sources" but a SINGLE compromised CEX API (whether via DNS hijack, credential compromise, or outright takeover) controls the oracle outright as long as it reports enough "volume". MAD outlier rejection does not save us — it uses the unweighted median ([aggregator/mod.rs:60](../src/aggregator/mod.rs#L60)) and lets anything within ~3·1.4826·MAD through. An attacker a fraction-of-a-percent off consensus passes the filter and then wins by weight.

This is the classic "price oracle trusts volume metric" pitfall; see public Euler audit findings on oracle-weight manipulation (OpenZeppelin, 2024).

**Fix.** Either (a) drop volume-weighting entirely and use the unweighted median of the honest set, which is what most production oracles do (Chainlink OCR2, RedStone); or (b) cap per-source weight at e.g. `min(reported_volume, P95_of_cross_source_volume)`; or (c) require multi-source volume agreement (reject a source whose volume exceeds 10× the next-highest).

---

## High findings

### H-1 — `maxAttestationAge = 365 days`

**Evidence.** [DeployGalleonReal.s.sol:30](../contracts/script/DeployGalleonReal.s.sol#L30): `uint256 maxAge = 365 days;` passed to `NitroAttestationVerifier`. Also `vm.envOr(..., bytes32(0))` for PCR1/PCR2 — see H-7.

**Impact.** AWS Nitro leaf certs in the attestation chain live ~3 hours. Setting the on-chain acceptance window to 365 days means any attestation document captured within the last year is re-usable. Combined with the PERMISSIONLESS [`registerEnclave`](../contracts/src/KaskadPriceOracle.sol#L110-L132), an attacker who sniffs `get_attestation` responses (host-side log, Slack paste, incident ticket) can re-register the enclave signer at will — including AFTER the legitimate enclave has rotated its key. This is a DoS (old signer has no private key anymore) or a worse primitive if the old key ever leaks.

**Fix.** `maxAge = 3 hours` matches the cert TTL. If the on-chain clock lags (Galleon note says up to 4 h), fix the clock — don't weaken the security invariant.

---

### H-2 — Per-asset min-sources NOT enforced on-chain

**Evidence.** Enclave-side [types.rs:82-89](../src/types.rs#L82-L89) enforces per-asset quora: ETH/BTC/KAS = 3, USDC = 2, IGRA = 1. On-chain [KaskadPriceOracle.sol:154-155](../contracts/src/KaskadPriceOracle.sol#L154-L155) only checks `numSources < 1`. A compromised, buggy or same-PCR-attacker enclave can sign ETH/USD with `numSources = 1`.

**PoC.** `test_POC_per_asset_min_sources_not_enforced_onchain` accepts `numSources = 1` for ETH/USD and BTC/USD.

**Fix.** Store a per-asset `minSources` mapping (or hard-code in contract) and revert if `numSources < minSources[assetId]`.

---

### H-3 — Rate limiter & future-timestamp cap claimed but not implemented

**Evidence.** [CLAUDE.md](../CLAUDE.md) line 35 ("rate limiter (5s), future timestamp cap (5 min)"). Neither exists in [KaskadPriceOracle.sol:143-207](../contracts/src/KaskadPriceOracle.sol#L143-L207). The existing test `test_rapid_updates_allowed` at [t.sol:298](../contracts/test/KaskadPriceOracle.t.sol#L298) asserts 10 s-apart updates PASS without ever checking that sub-5 s updates REVERT. The existing tests `test_future_timestamp_at_boundary_allowed` and `test_future_timestamp_allowed` ([t.sol:375-392](../contracts/test/KaskadPriceOracle.t.sol#L375-L392)) EXPLICITLY assert that future timestamps are accepted — which is C-3 disguised as a test.

**PoC.** `test_POC_no_rate_limiter_sub_5s_updates_accepted` (three updates in three seconds all pass) and `test_POC_no_future_timestamp_cap` (timestamp = T+1 year accepted).

**Fix.** Implement both. Rate limit: `require(block.timestamp - current.timestamp >= 5, "TooFrequent");` after the stale-timestamp check. Future cap: `require(timestamp <= block.timestamp + 5 minutes, "FutureTimestamp");`.

---

### H-4 — Circuit-breaker bypass after 4 h

**Evidence.** [KaskadPriceOracle.sol:167](../contracts/src/KaskadPriceOracle.sol#L167): `if (current.price > 0 && block.timestamp - current.timestamp < CIRCUIT_BREAKER_STALENESS) { …15% check… }`. The `else` branch silently skips the check.

**PoC.** `test_POC_circuit_breaker_bypass_after_4h_allows_1000x` — 4 h + 1 s of oracle silence → next update pumps price 1000× with `numSources = 1` (H-2 combo).

**Impact.** An attacker who can DoS the relayer or the enclave for 4 hours (network-level attack, GitHub cred compromise, compute-node downtime — realistic for a solo operator) gains a one-shot "push any price" primitive. Combined with C-4 (NaN → 0) this is catastrophic for Aave lenders.

**Fix.** Remove the staleness bypass. If the operator needs to resume after a long downtime, have them call an explicit `resumeAfterOutage(bytes calldata sig)` that requires a multi-source quorum update with tighter limits (e.g. 5 % per step, 3 steps to reach any target).

---

### H-5 — IGRA governance price from unattested runtime env var

**Evidence.**
- [main.rs:169-172](../src/main.rs#L169-L172): `IGRA_PRICE` read via `std::env::var`.
- [types.rs:85-99](../src/types.rs#L85-L99): `IgraUsd` has `min_sources = 1`, `deviation_threshold_bps = 0` (every update fires), `heartbeat = 86400`.
- AWS Nitro measures the EIF into PCR0-2, NOT arbitrary runtime environment variables. Dockerfile [line 24-25](../Dockerfile#L24-L25) sets `ENV RUST_LOG=info` and `ENV ENCLAVE_MODE=1` — but `IGRA_PRICE` is NOT baked into the Docker image, so it's injected at runtime from the parent.

**Impact.** Whoever controls the parent EC2 instance sets `IGRA_PRICE` to any value, and the enclave faithfully signs it with `numSources = 1`. The on-chain contract has no way to distinguish this from a legitimate governance update. If `NitroAttestationVerifier` is deployed with `expectedPCR2 = bytes32(0)` ([H-7](#h-7)), the operator can also swap the enclave image for a modified one that reads `IGRA_PRICE` from anywhere — same PCR0, different behaviour.

**Fix.** IGRA price should be a signed message from a pre-declared governance multisig, passed into the enclave via the VSOCK pull API and re-verified inside the enclave before signing. Runtime env vars in Nitro are ambient; they are unsuited for anything trust-critical.

---

### H-6 — MAD outlier rejection bypass by 3-of-N collusion

**Evidence.** [aggregator/mod.rs:52-76](../src/aggregator/mod.rs#L52-L76). Threshold = 3 × 1.4826 × MAD. MAD widens when attackers are present, so a small number of co-ordinated attackers can cluster inside the wider envelope without being rejected.

**PoC.** `POC_mad_collusion_shifts_median`: 4 honest at [1999.5, 2000, 2000.5, 2001] + 3 attackers at 2003 — all 7 survive MAD, median moves from 2000.25 (honest-only) to ~2001 (with attackers).

**Impact.** Moderate per-cycle shift (~0.04 %), but an attacker running 3 co-ordinated feeds (trivial with API-key compromise or DNS hijack on 3 minor CEXes) walks the median every cycle. Combined with the heartbeat/deviation trigger, the attacker can accumulate drift arbitrarily.

**Fix.** Robust alternatives: trimmed mean (drop top/bottom 20 %), biweight midvariance, or multi-round MAD with shrinking threshold. At minimum, require a stricter σ (1.5) so that 3-of-N attackers are rejected.

---

### H-7 — `expectedPCR1/PCR2 = bytes32(0)` permanently disables measurement

**Evidence.**
```solidity
// contracts/src/NitroAttestationVerifier.sol:78-79
if (expectedPCR1 != bytes32(0) && pcr1 != expectedPCR1) revert PCR1Mismatch();
if (expectedPCR2 != bytes32(0) && pcr2 != expectedPCR2) revert PCR2Mismatch();
```

`expectedPCR1/PCR2` are `immutable`. The deploy script ([DeployGalleonReal.s.sol:33-34](../contracts/script/DeployGalleonReal.s.sol#L33-L34)) defaults them to `bytes32(0)` via `vm.envOr("EXPECTED_PCR1", bytes32(0))`. Once deployed with zero, the check is bypassed PERMANENTLY — the verifier cannot be upgraded.

**Impact.** Only PCR-0 is checked (image EIF). An attacker who rebuilds the EIF with the same Dockerfile but a DIFFERENT kernel (PCR-1) or different init binary (PCR-2) generates a valid attestation that passes the verifier. Combined with H-5 (env-var driven behaviour), this is enough to subvert IGRA pricing entirely.

**Fix.** Make the verifier upgradeable via a multisig OR require non-zero PCR1/PCR2 at construction (`require(_expectedPCR1 != bytes32(0) && _expectedPCR2 != bytes32(0));`).

---

### H-8 — HTTP response size unbounded

**Evidence.** [http_client.rs:40](../src/http_client.rs#L40): `let body = resp.text().await?;` — no `.byte_limit()`, no streaming. reqwest default is unlimited.

**Impact.** A CEX under attacker control (DNS, TLS cert compromise, or outright ownership of a smaller exchange) returns an infinite response. The Nitro enclave (typically 512 MB – 32 GB) OOMs and restarts. Attacker pairs this with H-4 (4 h staleness bypass) — 4 h of enclave crash loops → free push of any price on next update.

**Fix.** `reqwest::Client::builder().response_body_limit(256_000)` (reqwest 0.12 supports this). Alternatively, `resp.bytes_stream()` + manual cap.

---

### H-9 — Host-controlled clock flows into signatures

**Evidence.** `now_secs()` = `SystemTime::now()` used at:
- [main.rs:44](../src/main.rs#L44): heartbeat / deviation trigger.
- [main.rs:48](../src/main.rs#L48): `(now_price - last_price) / last_price * 10000.0 as u16` — OK, but driven by the same clock.
- [price_server.rs:121](../src/price_server.rs#L121): timestamp fed to the signer on every `get_price` / `get_prices`.

[types.rs:13-15](../src/types.rs#L13-L15) comment claims `server_time` is the trusted clock — but `server_time` is NEVER read by the aggregator, deviation check, or signer.

**PoC.** `POC_heartbeat_underflow_on_clock_rewind` demonstrates u64 subtraction wrap — `now - last_ts` when `now < last_ts` yields a huge u64 in release mode, forcing a heartbeat push every cycle. A host that rewinds the clock creates a stream of signed updates — fodder for replay windows elsewhere.

**Impact.** All downstream "freshness" reasoning (deviation, heartbeat, `signedTimestamp` ordering) is at the mercy of the host clock. While the on-chain contract uses `block.timestamp` for its own checks, the SIGNED timestamp is host-controlled.

**Fix.** Use the median of source `server_time`s as the enclave's authoritative clock. Replace `now_secs()` everywhere in the signing path with `median_server_time(prices)`. Add a `checked_sub` around the heartbeat subtraction.

---

## Medium findings

### M-1 — Router sweeps pre-existing token balance

[KaskadRouter.sol:201-210](../contracts/src/KaskadRouter.sol#L201-L210) does `IERC20(seizedAsset).safeTransfer(msg.sender, balanceOf(this))` without tracking deltas from the pool call. Any tokens donated to the router contract (griefing, mis-send, failed partial recovery) are available to the next `liquidateWithPrices` caller.

**PoC.** `test_POC_router_sweeps_donated_tokens_on_liquidate` — griefer donates 1000 tokens, liquidator calls `liquidateWithPrices` with 1 wei debt; walks away with 1000 tokens.

**Fix.** Snapshot `balanceOf(this)` BEFORE the pool call, transfer only the delta after.

### M-2 — `to_fixed_point` saturates on overflow

[aggregator/mod.rs:80-83](../src/aggregator/mod.rs#L80-L83). Rust's saturating cast makes `f64::INFINITY → u128::MAX`, `f64 > 3.4e38 → u128::MAX`. `POC_fixed_point_saturates_on_overflow` + `POC_infinity_price_becomes_u128_max` demonstrate. Pair with C-4: the oracle never rejects a bogus extreme value, it silently clamps.

**Fix.** Early return `Err` if `price > MAX_SANE_PRICE` OR `!price.is_finite()`.

### M-3 — TxQueue marks reverted Tx as confirmed

[tx-queue.ts:79-89](../relayer/src/tx-queue.ts#L79-L89). `await tx.wait()` returns a receipt for BOTH successful and reverted Txs in ethers v6. The code never checks `receipt.status`. A reverted Tx is reported as `{status: "confirmed"}` to the FSM; the asset transitions back to IDLE without the on-chain price actually updating. Stale price persists on-chain while the relayer believes everything is fine.

**Fix.** `if (!receipt || receipt.status === 0) throw new Error("Reverted");`

### M-4 — Enclave-signer cache never refreshed

[relay.ts:29,46-54](../relayer/src/relay.ts#L29). Cached in memory; refreshed only if null. When the enclave rotates keys (operator-initiated redeploy, or H-1 triggered re-registration), the relayer's cached signer is stale → `verifySignature` rejects all fresh prices → relayer grinds to a halt until restart.

**Fix.** Refresh on every tick, or listen for `EnclaveRegistered` event and invalidate.

### M-5 — Non-positive volume disables weighting silently

[aggregator/mod.rs:17](../src/aggregator/mod.rs#L17) counts only `volume > 0.0` toward `sources_with_volume`. If half-or-more sources report zero-or-negative volume, `use_volume` flips to FALSE for that cycle — all sources weighted equally. An attacker who can influence half the sources' volume (e.g. 7 of 14 sources all reporting zero because of an outage) silently disables the volume scheme. `POC_non_positive_volume_flips_volume_weighting_off` demonstrates.

**Fix.** Log a WARN when `use_volume` flips; document the implicit mode-switch.

### M-6 — Sources bound only by URL for Bitfinex + Bitstamp

[bitfinex.rs:52-53](../src/sources/bitfinex.rs#L52): "the URL path is the only binding". Same for [bitstamp.rs](../src/sources/bitstamp.rs). If anything between the enclave and the CEX rewrites the response (proxy bug, TLS downgrade on a flaky cert chain, or a targeted MITM), the enclave cannot detect a swapped-pair response.

**Fix.** Cross-check `server_time` against a sanity window, and add a challenge path (e.g. fetch two different pairs and require distinct prices — catches blind-mirror attacks).

### M-7 — Attestation nonce = None

[signer.rs:169](../src/signer.rs#L169): `nonce: None`. AWS Nitro's attestation API supports a caller-provided nonce that is included in the signed doc. Without it, an attestation captured today can be replayed tomorrow at `registerEnclave` (up to `maxAttestationAge` = 365 days, H-1). This does not directly hand the attacker a key, but it widens the window for H-1 and makes forensic analysis harder.

**Fix.** Include `blockhash(block.number - 1)` from the chain as nonce. Inside the enclave, fetch it via the pull API's `/latest_blockhash` endpoint (exists or add).

### M-8 — PCR-0 truncated from 48 → 32 bytes

[NitroAttestationVerifier.sol:105-109](../contracts/src/NitroAttestationVerifier.sol#L105-L109). AWS Nitro PCR-0 is a 48-byte SHA-384. The contract stores `bytes32 pcr0 = first 32 bytes of pcrBytes`. Collision resistance falls from 2^192 (SHA-384) to 2^128 (32-byte truncation). Still safe today, but gratuitous reduction of the security margin. Also introduces a forgery surface if SHA-384 is ever broken for specific prefixes — a pathological concern.

**Fix.** Store `bytes32 pcr0_lo, pcr0_hi` (two slots, same SSTORE cost the first time).

---

## Low findings

### L-1 — Dead `run_vsock_tcp_bridge`

[main.rs:319-340](../src/main.rs#L319-L340) — function never called. Live bridge is inlined at [main.rs:136-161](../src/main.rs#L136-L161). Cleanup task, not a security issue on its own.

### L-2 — Even-count median bias

[aggregator/mod.rs:60](../src/aggregator/mod.rs#L60) picks the UPPER middle for even-length. `POC_reject_outliers_even_count_upper_bias` documents. Minor asymmetry in MAD threshold.

### L-3 — `sources_hash` endianness mix

[aggregator/mod.rs:93](../src/aggregator/mod.rs#L93): `p.price.to_le_bytes()` on an f64 inside a keccak that's otherwise big-endian. Not a vulnerability — only an inconsistency that complicates on-chain verification if ever added.

### L-4 — HTTP client defaults

[http_client.rs:17-33](../src/http_client.rs#L17-L33). No explicit `redirect::Policy::limited(3)`, no body size limit (H-8), no connect/read timeout split. Reqwest defaults are OK but not audit-grade.

---

## Out-of-scope / observed but not exploited

- **VSOCK listener uses libc directly ([price_server.rs:279-336](../src/price_server.rs#L279-L336)).** `listen(fd, 5)` backlog = 5 — fine for a single relayer. `setsockopt(SO_REUSEADDR)` but no `SO_REUSEPORT` — OK.
- **NSM entropy.** [Dockerfile:38-43](../Dockerfile#L38-L43) explicitly aborts if `/sys/devices/virtual/misc/hw_random/rng_current != nsm-hwrng`. Good defensive practice, not a finding.
- **`k256::ecdsa`.** Using `sign_prehash_recoverable` — correct for EIP-191. RFC-6979 deterministic nonces by default. No RNG-dependent signing path.
- **Relayer: unlimited API response size (H-8 parallel).** [relayer/src/poll.ts:37](../relayer/src/poll.ts#L37) `.json()` has no cap either. Same fix pattern.
- **Dockerfile `ENV ENCLAVE_MODE=1`** is baked in, so PCR-0 covers it. Good.

---

## Reproduction

```bash
# Solidity
cd contracts
forge test --match-contract SecurityAuditTest -vvv
# Expected: 7/7 passed

# Rust
cd ..
cargo test --test security_audit
# Expected: 11/11 passed
```

Both suites currently pass; each test EXISTS because the production code is vulnerable. When the corresponding fix is applied, the test should be inverted (assertion flipped to `expect_revert` / `assertNe`) to guard against regression.

---

## Priority recommendations

1. **Do not ship to mainnet** until C-1 (Galleon has no TEE trust) is resolved — i.e. NitroAttestationVerifier actually verifies real attestations.
2. **Before re-deploying,** fix C-2 (domain separator), C-3 + H-3 (future-ts cap), C-4 (NaN/Infinity rejection), H-2 (per-asset quorum), H-4 (drop staleness bypass), H-5 (governance price path), H-7 (require non-zero PCR1/PCR2), H-8 (response size limit).
3. **Before any cross-chain expansion,** implement EIP-712 domain separator (C-2).
4. **Operational:** add a `security.txt`-style disclosure policy, and get a second pair of eyes on the Marlin NitroProver integration (beyond this audit's scope — per memory note, there is a live P-384 verification blocker on Galleon).
