{ n }:
let
  mkOne = i: derivation {
    name = "closure-fixture-${toString i}";
    system = builtins.currentSystem;
    builder = "/bin/sh";
    args = [ "-c" "echo closure fixture content ${toString i} > $out" ];
  };
in
  builtins.genList mkOne n
