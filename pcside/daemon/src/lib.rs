//! Library surface for the r503d daemon. Exposes the modules needed by
//! integration tests, examples, and cross-verify helpers. The binary itself
//! does not depend on this lib (it includes modules directly via `mod`), so
//! the same source files compile twice — once into the bin crate, once into
//! the lib crate. Acceptable for now; consolidate after Milestone E if it
//! becomes a hot spot.

pub mod crypto;
pub mod framing;
pub mod keystore;
pub mod state;
pub mod tpm;
