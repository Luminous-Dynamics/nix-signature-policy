//! Library components for the `nix-signature-policy` reference implementation, split out from the CLI binary so
//! integration tests (`tests/`) and benchmarks (`benches/`) can exercise the
//! narinfo/keys/proxy logic directly instead of shelling out to the binary.

pub mod artifact_attestation;
pub mod commitment;
pub mod conformance;
pub mod core;
pub mod evidence;
pub mod governance;
pub mod hybrid;
pub mod integration;
pub mod keys;
pub mod limits;
pub mod narinfo;
pub mod policy;
pub mod policy_adapters;
pub mod protocol;
pub mod proxy;
pub mod receipt;
pub mod registry;
pub mod state;
