//! Library half of `nix-pqc-cache-proxy`, split out from the CLI binary so
//! integration tests (`tests/`) and benchmarks (`benches/`) can exercise the
//! narinfo/keys/proxy logic directly instead of shelling out to the binary.

pub mod hybrid;
pub mod keys;
pub mod narinfo;
pub mod proxy;
