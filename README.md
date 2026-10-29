# Kaskad Nuntius

Nuntius is Kaskad's price oracle. It runs in AWS Nitro Enclaves, collects prices from public exchanges and aggregators, and signs each price with a key that exists only inside enclaves. Anyone can fetch the signed prices over HTTPS and submit them to the oracle contract, which accepts only prices signed by a registered enclave key.

This repository holds the oracle enclave, the Pontifex bridge enclave, and their tests. The contracts are in the `contracts` submodule, [Kaskad-Lending/kaskad-nuntius-contracts](https://github.com/Kaskad-Lending/kaskad-nuntius-contracts).

- [Oracle](https://docs.kaskad.app/docs/oracle-integration): how prices are produced and what keeps them safe.
- [Oracle API Reference](https://docs.kaskad.app/docs/oracle-api): endpoints, the signature format, the contracts, and code examples.
- [Enclave Security](https://docs.kaskad.app/docs/enclave-security): keys, attestation and the role of the host.
- [Verify the Enclaves](https://docs.kaskad.app/docs/enclave-verification): rebuild the images and check them against the live attestations and the on-chain pins.

## How It Works

1. For each asset, the enclave fetches quotes from a fixed list of sources over TLS. The list is in `config/assets.json` and `config/exchanges.json`, which are compiled into the image, so the attestation covers them.
2. It removes outliers and takes the volume-weighted median of the remaining quotes. The [Oracle](https://docs.kaskad.app/docs/oracle-integration#how-a-price-is-computed) page describes each step and how the Igra and Robinhood Chain images differ.
3. It signs the result with EIP-191 over `abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)`. The signing key is bound to the enclave's attestation document, and the oracle contract registers the key from that document.
4. The host serves the signed prices over HTTPS. The enclave sends no transactions. Anyone can submit a price, and the contract checks the signer, the number of sources, the order of updates and the change limits.

## Keys

- **Robinhood Chain.** While the oracle contract has no registered signer, an oracle enclave generates the root key from the Nitro hardware random number generator. Enclaves running the same image receive the key from a running enclave over RA-TLS. The key exists only in enclave memory. The Pontifex bridge key is derived from it.
- **Igra.** Each regional enclave generates its own key and stores it encrypted with AWS KMS.

## Images

| Dockerfile | Image |
|---|---|
| `Dockerfile.oracle` | The oracle on Robinhood Chain, built with `--features keyex_oracle` |
| `Dockerfile.pontifex` | The Pontifex bridge enclave |
| `Dockerfile` | The oracle with KMS key storage, the design used on Igra |

The source of the live Robinhood Chain images and their build arguments are published in [Kaskad-Lending/kaskad-pontifex-enclave](https://github.com/Kaskad-Lending/kaskad-pontifex-enclave/tree/79c81b806232c325b3b4b01c9d47cb8713e71063). [Verify the Enclaves](https://docs.kaskad.app/docs/enclave-verification) rebuilds both images from it and compares their PCRs with the live attestations and the on-chain pins.

## Repository Layout

```
src/                      the oracle
  sources/                one module per price source
  collectors/, cob.rs     exchange order books and the consolidated-order-book price
  aggregator/             outlier removal and the volume-weighted median
  signer.rs               price signatures
  keyex_oracle/           Robinhood Chain key generation and handover
  sealing.rs              Igra key storage with AWS KMS
crates/keyex/             RA-TLS key handover and the boot rules shared by both enclaves
crates/nitro-common/      Nitro Security Module access and attestation verification
crates/pontifex-bridge/   the Pontifex bridge enclave
config/                   assets and sources, compiled into the image
contracts/                submodule: kaskad-nuntius-contracts
tests/, testdata/         integration tests and attestation fixtures
```

`enclave/` and `infra/` hold Kaskad's host tooling and infrastructure code, `relayer/` a price relayer, and `scripts/` end-to-end test scripts. The commands in this README do not use them.

## Build and Test

```bash
git clone --recursive https://github.com/Kaskad-Lending/kaskad-nuntius.git
cd kaskad-nuntius
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --all-targets --features keyex_oracle -- -D warnings
cargo test --workspace
cargo test --features keyex_oracle
(cd contracts && forge test)
```

`rust-toolchain.toml` pins Rust 1.91.1.

## Run a Pricing Round Locally

```bash
KASKAD_ALLOW_MOCK_SIGNER=1 SINGLE_RUN=1 cargo run
```

This runs one pricing round on your machine and logs the price and the number of sources for each asset. The process keeps running after `Single run complete`; stop it with Ctrl-C. It uses a random signing key, which no Kaskad contract has registered.

## Run Your Own Oracle

To run your own Nuntius, with your own assets, sources or approvers, you deploy your own oracle contract and run your own enclave image. This section is an outline of the Robinhood Chain flow. You also need to run the parent-instance side yourself: relaying the enclave's outbound connections to its sources and RPC endpoints, and serving its signed prices.

1. **Choose the assets and sources** in `config/assets.json` and `config/exchanges.json`. Any change gives the image a different PCR0.
2. **Predict your oracle's address**, as in step 1 of [Deploy on Robinhood Chain](https://github.com/Kaskad-Lending/kaskad-nuntius-contracts#deploy-on-robinhood-chain) in the contracts README.
3. **Build `Dockerfile.oracle`** with your own build arguments. They are compiled into the binary, so they are part of PCR0, and the enclave refuses to start if a required one is missing or malformed. The build command in the kaskad-pontifex-enclave README is a template. The build requires `SOURCE_DATE_EPOCH`, which fixes file times so that PCR0 is reproducible.

   | Build argument | Value |
   |---|---|
   | `KEYEX_ORACLE_REGISTRY` | Your oracle's predicted address |
   | `KEYEX_ORACLE_RH_RPCS` | Comma-separated HTTPS RPC endpoints through which the enclave reads the oracle contract and the Safe |
   | `KEYEX_ORACLE_CHAIN_ID` | The chain ID that owner approvals must name: `4663`, or `46630` for the testnet |
   | `KEYEX_ORACLE_SAFE`, `KEYEX_ORACLE_OWNERS`, `KEYEX_ORACLE_THRESHOLD` | The Safe, its owners and the minimum number of owner approvals before an enclave hands its key, or a key derived from it, to a different image |
   | `KEYEX_ORACLE_VERSION` | The image version, `1` for a first image |
   | `KEYEX_ORACLE_ANCESTORS`, `KEYEX_ORACLE_PEERS` | Earlier images and running enclaves that this image may take the key from. Empty for a first image |

4. **Deploy the oracle contract** pinned to the image's PCR0, as in step 3 of the contracts README.
5. **Run the image** in a Nitro Enclave. On its first boot it generates the key and produces an attestation document that binds it.
6. **Register the key** from that attestation document, as in step 5 of the contracts README. The enclave starts signing prices once its key is registered.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
