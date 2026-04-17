# contracts/external

Companion Solidity contracts mirrored from `../lending-onchain/src/oracle/`.
They live here as a convenience stash so everything related to the Kaskad
oracle stack is reachable from this repo while the longer-term
home (a dedicated oracle-contracts repo) is being set up.

**These files are NOT compiled by forge** — they sit outside
`contracts/src/`, `contracts/test/`, and `contracts/script/` on purpose.
Both depend on `@aave-v3-origin` which isn't vendored here. Copy them back
into `lending-onchain` (or the future oracle-contracts repo) to build.

- [KaskadStalenessChecker.sol](./KaskadStalenessChecker.sol) — implements
  Aave's `IPriceOracleSentinel`; reads `KaskadRouter.sender()` from
  transient storage to narrow freshness checks to the caller's assets.
- [UiDataProviderWrapper.sol](./UiDataProviderWrapper.sol) — single-eth_call
  wrapper that pushes fresh enclave prices then reads protocol state.

Keep the SPDX headers as MIT (upstream source) — the main oracle stack is
Apache-2.0 but these specific files came in under MIT and should retain
that attribution.
