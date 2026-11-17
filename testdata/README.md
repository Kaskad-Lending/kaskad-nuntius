# Attestation fixtures

Recorded AWS Nitro attestation documents, hex-encoded COSE_Sign1, used by the
`nitro-common` and `keyex` unit tests.

| file | enclave | signer |
|---|---|---|
| `attestation-us.hex` | live Igra oracle, us-east-1 | `0x544705f5d72e1c6f24bfd7c2e176f2cd2aa8dc2a` |
| `attestation-eu.hex` | live Igra oracle, eu-west-1 | `0xd35e55c7c2d10472e6d9e7132c88beed347d91a7` |

Public data: a COSE document, its certificate chain and PCRs. No secret material.
Leaf validity ends a few hours after capture, so the tests pin
`NOW = 1789682698` (2026-09-17 22:04:58Z) instead of reading the clock. The same
bytes live in `kaskad-pontifex/test/fixtures` for the Solidity verifier tests.

# VUSD NAV fixtures

Byte-identical copies of the VUSD/USD spec files, used by `src/sources/ethrpc.rs` tests.

| file | content |
|---|---|
| `vusd_nav_fixtures.json` | 42 response vectors with the expected price or reject reason |
| `vusd_nav_calldata.hex` | Multicall3 `aggregate` calldata sent to every RPC operator |
