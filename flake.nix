{
  description = "nix-signature-policy — reproducible composable signature-authorization prototype";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        lib = pkgs.lib;

        manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        toolchainSpec = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
        rustChannel = toolchainSpec.toolchain.channel;

        # rust-toolchain.toml is the single source of truth for the compiler
        # floor. The flake consumes the same version rather than silently using
        # whatever Rust happens to be current in nixpkgs.
        rustToolchain = pkgs.rust-bin.stable.${rustChannel}.default.override {
          extensions = [ "clippy" "rust-src" "rustfmt" ];
        };
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
        # Fuzzing is intentionally isolated from the stable compiler floor.
        # The date pin is deterministic under the locked rust-overlay input.
        fuzzToolchain = pkgs.rust-bin.nightly."2026-03-15".default.override {
          extensions = [ "rust-src" "rustfmt" ];
        };

        pname = manifest.package.name;
        version = manifest.package.version;
        source = lib.cleanSource ./.;
        policySchemaPython = pkgs.python3.withPackages (pythonPackages: [
          pythonPackages.jsonschema
        ]);

        common = {
          inherit pname version;
          src = source;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          strictDeps = true;
          RUST_BACKTRACE = "1";
        };

        package = rustPlatform.buildRustPackage (common // {
          doCheck = true;
          meta = {
            description = manifest.package.description;
            homepage = "https://github.com/Luminous-Dynamics/nix-signature-policy";
            license = lib.licenses.agpl3Plus;
            mainProgram = "nix-pqc-cache-proxy";
            platforms = lib.platforms.unix;
          };
        });

        # Every flake check receives the exact Cargo.lock dependency closure
        # through buildRustPackage's vendoring hook. This keeps `nix flake
        # check` network-free after the flake inputs and crate sources are in
        # the Nix store.
        mkCargoCheck = name: command:
          rustPlatform.buildRustPackage (common // {
            pname = "${pname}-${name}";
            doCheck = false;
            dontCargoBuild = true;
            buildPhase = ''
              runHook preBuild
              export RUSTFLAGS="-D warnings"
              export RUSTDOCFLAGS="-D warnings"
              ${command}
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p "$out"
              printf '%s\n' '${name} passed' > "$out/result"
              runHook postInstall
            '';
          });

        mkLocalApp = { name, description, runtimeInputs, text }:
          let
            script = pkgs.writeShellApplication {
              inherit name runtimeInputs text;
              meta.description = description;
            };
          in
          {
            type = "app";
            program = "${script}/bin/${name}";
            meta.description = description;
          };

        mkRealNixApp = label: nixPackage:
          mkLocalApp {
            name = "nix-pqc-real-e2e-${label}";
            description = "Run the real-Nix proof with the pinned ${label} Nix package";
            runtimeInputs = [
              nixPackage
              rustToolchain
              pkgs.cacert
              pkgs.coreutils
              pkgs.git
              pkgs.hello
              pkgs.python3
            ];
            text = ''
              set -euo pipefail
              export RUST_BACKTRACE=1
              export NIX_CONFIG=$'experimental-features = nix-command flakes\nwarn-dirty = false'
              export NIX_PQC_E2E_STORE_PATH="${pkgs.hello}"

              echo "Rust: $(rustc --version)"
              echo "Nix:  $(nix --version)"
              echo "Path: $NIX_PQC_E2E_STORE_PATH"
              cargo test --locked --test real_nix_e2e -- --ignored --nocapture
            '';
          };

        devPackages = [
          rustToolchain
          pkgs.cacert
          pkgs.cargo-audit
          pkgs.cargo-nextest
          pkgs.diffutils
          pkgs.git
          pkgs.jq
          pkgs.nixVersions.stable
          pkgs.nixpkgs-fmt
          policySchemaPython
          pkgs.ripgrep
        ];
      in
      {
        packages.default = package;

        apps.default = {
          type = "app";
          program = "${package}/bin/nix-pqc-cache-proxy";
          meta.description = manifest.package.description;
        };

        apps.check = mkLocalApp {
          name = "nix-pqc-check";
          description = "Run the same fast Rust validation commands represented by flake checks";
          runtimeInputs = devPackages;
          text = ''
            set -euo pipefail
            export RUST_BACKTRACE=1
            export RUSTFLAGS="-D warnings"
            export RUSTDOCFLAGS="-D warnings"
            python3 scripts/check-positioning.py
            python3 scripts/check-policy-vector-schema.py
            python3 scripts/check-evidence-schema.py
            python3 scripts/check-fuzz-layout.py
            python3 scripts/check-operational-hardening.py
            python3 scripts/check-release-engineering.py
            python3 scripts/check-integration-contract.py
            python3 scripts/check-trust-receipts.py
            python3 scripts/check-trust-state.py
            python3 scripts/build-policy-manifest.py --check
            python3 scripts/check-semantic-consistency.py
            python3 scripts/check-core-profile.py
            python3 scripts/check-commitment-vectors.py
            python3 scripts/check-review-package.py
            python3 scripts/check-reference-model.py
            python3 scripts/check-distinct-relation-matching-performance.py
            python3 scripts/check-authorization-protocol.py
            python3 scripts/check-transition-governance.py
            python3 scripts/build-differential-corpus.py --check
            python3 scripts/check-differential-corpus.py
            python3 scripts/check-resource-profile.py
            python3 scripts/check-integration-vectors.py
            python3 scripts/check-package-identity.py
            cargo run --locked --bin policy-conformance -- --vectors policy-vectors --format json >/dev/null
            tmpdir="$(mktemp -d)"
            trap 'rm -rf "$tmpdir"' EXIT
            cargo run --locked --bin policy-evidence -- export-vector \
              policy-vectors/adapter-parity/semantic-hybrid-valid.json \
              --out "$tmpdir/evidence.json"
            cmp "$tmpdir/evidence.json" evidence/examples/semantic-hybrid-valid.evidence.json
            cargo run --locked --bin policy-evidence -- verify \
              "$tmpdir/evidence.json" \
              --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
              --require-source --format json >/dev/null
            cargo fmt --all -- --check
            cargo clippy --all-targets --locked -- -D warnings
            cargo test --locked
            cargo check --benches --examples --locked
            cargo doc --no-deps --locked
          '';
        };

        apps.real-nix-e2e = mkRealNixApp "stable" pkgs.nixVersions.stable;
        apps.real-nix-e2e-stable = mkRealNixApp "stable" pkgs.nixVersions.stable;
        apps.real-nix-e2e-latest = mkRealNixApp "latest" pkgs.nixVersions.latest;

        apps.demo = mkLocalApp {
          name = "nix-pqc-demo";
          description = "Run the evidence-producing real-Nix maintainer demonstration";
          runtimeInputs = [
            pkgs.nixVersions.stable
            rustToolchain
            pkgs.cacert
            pkgs.coreutils
            pkgs.git
            pkgs.hello
            pkgs.python3
          ];
          text = ''
            set -euo pipefail
            export RUST_BACKTRACE=1
            export NIX_CONFIG=$'experimental-features = nix-command flakes\nwarn-dirty = false'
            export NIX_PQC_E2E_STORE_PATH="${pkgs.hello}"
            exec scripts/demo-real-nix.sh "$@"
          '';
        };

        apps.release-source = mkLocalApp {
          name = "nix-pqc-release-source";
          description = "Build a deterministic source-only release from the current clean Git checkout";
          runtimeInputs = [
            package
            rustToolchain
            pkgs.git
            pkgs.nixVersions.stable
            pkgs.python3
          ];
          text = ''
            set -euo pipefail
            exec python3 scripts/build-source-release.py "$@"
          '';
        };

        apps.verify-release = mkLocalApp {
          name = "nix-pqc-verify-release";
          description = "Verify a source release manifest and optional hybrid release attestation";
          runtimeInputs = [ package pkgs.python3 ];
          text = ''
            set -euo pipefail
            exec python3 scripts/verify-source-release.py "$@"
          '';
        };

        apps.artifact-attestation = {
          type = "app";
          program = "${package}/bin/artifact-attestation";
          meta.description = "Create and verify hybrid attestations over release statements";
        };


        apps.fuzz-smoke = mkLocalApp {
          name = "nix-pqc-fuzz-smoke";
          description = "Run bounded libFuzzer smoke campaigns for parser and policy boundaries";
          runtimeInputs = [ fuzzToolchain pkgs.cargo-fuzz pkgs.coreutils ];
          text = ''
            set -euo pipefail
            exec scripts/fuzz-smoke.sh
          '';
        };

        apps.policy-conformance = mkLocalApp {
          name = "nix-pqc-policy-conformance";
          description = "Run representation-neutral adversarial signature-policy vectors";
          runtimeInputs = [ package ];
          text = ''
            set -euo pipefail
            exec policy-conformance --vectors ${source}/policy-vectors "$@"
          '';
        };

        apps.policy-evidence = {
          type = "app";
          program = "${package}/bin/policy-evidence";
          meta.description = "Export and verify deterministic policy-decision evidence bundles";
        };

        apps.trust-state = {
          type = "app";
          program = "${package}/bin/trust-state";
          meta.description = "Manage local rollback-resistant policy and registry checkpoints";
        };

        apps.signature-authorize = {
          type = "app";
          program = "${package}/bin/nix-signature-authorize";
          meta.description = "Evaluate one bounded normalized signature-authorization request";
        };

        apps.environment = mkLocalApp {
          name = "nix-pqc-environment";
          description = "Emit machine-readable toolchain and lock provenance";
          runtimeInputs = [ rustToolchain pkgs.nixVersions.stable pkgs.python3 ];
          text = ''
            set -euo pipefail
            exec python3 scripts/report-environment.py
          '';
        };

        apps.audit = mkLocalApp {
          name = "nix-pqc-audit";
          description = "Audit the locked Rust dependency graph for known advisories";
          runtimeInputs = [ rustToolchain pkgs.cargo-audit pkgs.cacert ];
          text = ''
            set -euo pipefail
            cargo audit
          '';
        };

        checks = {
          inherit package;

          fmt = mkCargoCheck "fmt" ''
            cargo fmt --all -- --check
          '';

          clippy = mkCargoCheck "clippy" ''
            cargo clippy --all-targets --locked -- -D warnings
          '';

          # The package derivation runs the ordinary hermetic test suite in
          # its check phase; alias it so the same derivation is not rebuilt.
          test = package;

          benches-and-examples = mkCargoCheck "benches-and-examples" ''
            cargo check --benches --examples --locked
          '';

          docs = mkCargoCheck "docs" ''
            cargo doc --no-deps --locked
          '';


          proxy-operational = mkCargoCheck "proxy-operational" ''
            cargo test --locked --test proxy_e2e
          '';


          fuzz-layout = pkgs.runCommand "${pname}-fuzz-layout" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-fuzz-layout.py
            mkdir -p "$out"
            printf '%s\n' 'fuzz layout check passed' > "$out/result"
          '';

          evidence-schema = pkgs.runCommand "${pname}-evidence-schema" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/check-evidence-schema.py
            mkdir -p "$out"
            printf '%s\n' 'evidence schema check passed' > "$out/result"
          '';

          policy-vector-schema = pkgs.runCommand "${pname}-policy-vector-schema" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/check-policy-vector-schema.py
            mkdir -p "$out"
            printf '%s\n' 'policy-vector schema check passed' > "$out/result"
          '';

          trust-state-schema = pkgs.runCommand "${pname}-trust-state-schema" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/check-trust-state.py
            mkdir -p "$out"
            printf '%s\n' 'trust-state schema check passed' > "$out/result"
          '';

          semantic-consistency = pkgs.runCommand "${pname}-semantic-consistency" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/build-policy-manifest.py --check
            python3 scripts/check-semantic-consistency.py
            mkdir -p "$out"
            printf '%s\n' 'semantic consistency check passed' > "$out/result"
          '';

          core-profile = pkgs.runCommand "${pname}-core-profile" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/check-core-profile.py
            mkdir -p "$out"
            printf '%s\n' 'core-v1 profile check passed' > "$out/result"
          '';
          commitment-vectors = pkgs.runCommand "${pname}-commitment-vectors" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-commitment-vectors.py
            mkdir -p "$out"
            printf '%s\n' 'commitment vectors passed' > "$out/result"
          '';
          review-package = pkgs.runCommand "${pname}-review-package" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-review-package.py
            mkdir -p "$out"
            printf '%s\n' 'review package check passed' > "$out/result"
          '';
          reference-model = pkgs.runCommand "${pname}-reference-model" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-reference-model.py
            mkdir -p "$out"
            printf '%s\n' 'independent reference model passed' > "$out/result"
          '';
          authorization-protocol = pkgs.runCommand "${pname}-authorization-protocol" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-authorization-protocol.py
            mkdir -p "$out"
            printf '%s\n' 'bounded authorization protocol passed' > "$out/result"
          '';
          transition-governance = pkgs.runCommand "${pname}-transition-governance" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-transition-governance.py
            mkdir -p "$out"
            printf '%s\n' 'transition governance passed' > "$out/result"
          '';
          differential-conformance = pkgs.runCommand "${pname}-differential-conformance" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/build-differential-corpus.py --check
            python3 scripts/check-differential-corpus.py
            mkdir -p "$out"
            printf '%s\n' 'differential conformance passed' > "$out/result"
          '';
          resource-profile = pkgs.runCommand "${pname}-resource-profile" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-resource-profile.py
            mkdir -p "$out"
            printf '%s\n' 'resource profile passed' > "$out/result"
          '';
          integration-vectors = pkgs.runCommand "${pname}-integration-vectors" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-integration-vectors.py
            mkdir -p "$out"
            printf '%s\n' 'integration decision matrix passed' > "$out/result"
          '';
          package-identity = pkgs.runCommand "${pname}-package-identity" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-package-identity.py
            mkdir -p "$out"
            printf '%s\n' 'package identity passed' > "$out/result"
          '';
          policy-conformance = mkCargoCheck "policy-conformance" ''
            cargo run --locked --bin policy-conformance -- \
              --vectors policy-vectors --format json > policy-report.json
          '';

          policy-evidence-roundtrip = mkCargoCheck "policy-evidence-roundtrip" ''
            cargo run --locked --bin policy-evidence -- export-vector \
              policy-vectors/adapter-parity/semantic-hybrid-valid.json \
              --out policy-evidence.json
            cmp policy-evidence.json evidence/examples/semantic-hybrid-valid.evidence.json
            cargo run --locked --bin policy-evidence -- verify \
              policy-evidence.json \
              --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
              --require-source --format json > policy-evidence-report.json
          '';

          positioning = pkgs.runCommand "${pname}-positioning" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-positioning.py
            mkdir -p "$out"
            printf '%s\n' 'prior-art positioning check passed' > "$out/result"
          '';


          operational-hardening = pkgs.runCommand "${pname}-operational-hardening" {
            nativeBuildInputs = [ pkgs.python3 ];
          } ''
            cd ${source}
            python3 scripts/check-operational-hardening.py
            mkdir -p "$out"
            printf '%s\n' 'operational hardening guard passed' > "$out/result"
          '';

          release-engineering = pkgs.runCommand "${pname}-release-engineering" {
            nativeBuildInputs = [ policySchemaPython ];
          } ''
            cd ${source}
            python3 scripts/check-release-engineering.py
            python3 - <<'PY'
import json
from jsonschema import Draft202012Validator
for path in ("release/schema-v1.json", "release/attestation-schema-v1.json"):
    schema = json.load(open(path))
    Draft202012Validator.check_schema(schema)
PY
            mkdir -p "$out"
            printf '%s\n' 'release engineering guard passed' > "$out/result"
          '';
        };

        devShells.default = pkgs.mkShell {
          name = "nix-signature-policy-dev";
          packages = devPackages ++ [ pkgs.rust-analyzer ];
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          shellHook = ''
            export RUST_BACKTRACE=1
            cat <<'BANNER'
            nix-signature-policy development shell

              nix flake check             # hermetic package + fmt/clippy/test/docs
              nix run .#check              # same commands interactively
              nix run .#real-nix-e2e-stable
              nix run .#fuzz-smoke         # bounded nightly fuzz campaigns
              nix run .#real-nix-e2e-latest
              nix run .#audit
              nix run .#environment
              nix run .#policy-conformance
              nix run .#policy-evidence -- --help
              nix run .#demo -- --out-dir demo-output
              nix run .#release-source -- --out-dir dist
              nix run .#verify-release -- dist/<release>.release.json
              python3 scripts/check-positioning.py
              python3 scripts/check-policy-vector-schema.py
              python3 scripts/check-evidence-schema.py
              python3 scripts/check-operational-hardening.py
              python3 scripts/check-release-engineering.py
              python3 scripts/check-integration-contract.py
              python3 scripts/check-trust-receipts.py
              python3 scripts/check-trust-state.py
              python3 scripts/build-policy-manifest.py --check
              python3 scripts/check-semantic-consistency.py
              python3 scripts/check-core-profile.py
              python3 scripts/check-commitment-vectors.py
              python3 scripts/check-review-package.py
              python3 scripts/check-reference-model.py
              python3 scripts/check-authorization-protocol.py
              python3 scripts/check-transition-governance.py
              python3 scripts/build-differential-corpus.py --check
              python3 scripts/check-differential-corpus.py
              python3 scripts/check-resource-profile.py
              python3 scripts/check-integration-vectors.py
              python3 scripts/check-package-identity.py
            BANNER
          '';
        };

        devShells.fuzz = pkgs.mkShell {
          name = "nix-signature-policy-fuzz";
          packages = [ fuzzToolchain pkgs.cargo-fuzz pkgs.git ];
          RUST_SRC_PATH = "${fuzzToolchain}/lib/rustlib/src/rust/library";
          shellHook = ''
            export RUST_BACKTRACE=1
            echo "nightly fuzz shell: cargo fuzz run <target>"
          '';
        };

        devShells.ci = pkgs.mkShell {
          name = "nix-signature-policy-ci";
          packages = devPackages;
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          RUST_BACKTRACE = "1";
        };
      });
}
