//! Placeholder used during the multi-phase rewrite.
//!
//! Existing exchanges that haven't been ported yet to the `Collector` trait
//! return `None` from the factory and stay disabled in the oracle. Once
//! ported, their match arm is replaced with the real impl.
