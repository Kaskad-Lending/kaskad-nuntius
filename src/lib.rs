//! Library facet of `kaskad-oracle`.
//!
//! The crate ships a binary (`src/main.rs`) as its primary target — every
//! enclave/runtime concern lives there. This thin `lib.rs` re-exports only
//! the pure-compute modules so the integration tests under `tests/` can
//! assert production behaviour directly instead of duplicating the
//! aggregator routines and drifting out of sync.
//!
//! Modules listed here are also declared inside `main.rs` — cargo compiles
//! each one once per target. That's deliberate and cheap: the modules are
//! pure-compute and free of global state, so the two compilations produce
//! independent but equivalent code (the `EQUAL_WEIGHT_FALLBACK_COUNT`
//! statics live in separate namespaces — the integration tests see only
//! the lib's copy, which is exactly the surface they assert on).

pub mod aggregator;
pub mod types;
