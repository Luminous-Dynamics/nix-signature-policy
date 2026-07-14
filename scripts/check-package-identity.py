#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
cargo=(root/'Cargo.toml').read_text()
assert 'name = "nix-signature-policy"' in cargo
assert 'default-run = "nix-pqc-cache-proxy"' in cargo
assert 'name = "nix_signature_policy"' in cargo
lock=(root/'Cargo.lock').read_text(); assert 'name = "nix-signature-policy"\nversion = "0.1.0"' in lock
for p in [*root.joinpath('src').rglob('*.rs'),*root.joinpath('tests').rglob('*.rs'),*root.joinpath('fuzz').rglob('*.rs'),*root.joinpath('examples').rglob('*.rs'),*root.joinpath('benches').rglob('*.rs')]:
 assert 'nix_pqc_cache_proxy' not in p.read_text(), p
sync=(root/'scripts/sync-to-standalone.sh').read_text()
assert 'Luminous-Dynamics/nix-signature-policy.git' in sync
assert '/nix-signature-policy' in sync
flake=(root/'flake.nix').read_text()
assert 'mainProgram = "nix-pqc-cache-proxy";' in flake
assert 'program = "${package}/bin/nix-pqc-cache-proxy";' in flake
assert 'nix-pqc-cache-proxy/artifact-attestation/v1' in (root/'src/artifact_attestation.rs').read_text()
assert 'nix-pqc-cache-proxy/policy-evidence/v1' in (root/'src/evidence.rs').read_text()
assert 'dist/nix-signature-policy-VERSION.release.json' in (root/'README.md').read_text()
assert 'name = "nix-signature-policy-dev";' in flake
print('package identity and legacy protocol domains are consistent')
