#!/bin/sh
# Trivial O-process provider: echoes a fixed, shape-valid response without
# doing any real cryptographic work or process startup beyond a shell.
# Used to isolate "process/IPC boundary cost" from "real verifier binary
# cost" -- the same methodological shape as H's own trivial accept-hook.sh,
# applied to the O-process transport for a fair boundary-only comparison.
cat > /dev/null
echo '{"candidates":[{"key_name":"acme-release-ed25519-1","algorithm":"ed25519","signature_id":"0000000000000000000000000000000000000000000000000000000000000000","verification":"valid"}]}'
