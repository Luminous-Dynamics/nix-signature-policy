#!/usr/bin/env bash
# Builds the example Model O-provider shared libraries used by the
# authorization-boundary-architecture comparison's E2E tests. Not part
# of Nix's own build -- a real provider is an out-of-tree artifact
# compiled independently, and building it that way here is more
# representative than wiring it into Nix's meson build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ABI_HEADER_DIR="."
SODIUM_CFLAGS=$(pkg-config --cflags libsodium)
SODIUM_LIBS=$(pkg-config --libs libsodium)

cc -shared -fPIC -Wall -Wextra -O2 \
    -I "$ABI_HEADER_DIR" $SODIUM_CFLAGS \
    example-provider.c $SODIUM_LIBS \
    -o libexample-provider.so

cc -shared -fPIC -Wall -Wextra -O2 \
    -I "$ABI_HEADER_DIR" \
    crash-provider.c \
    -o libcrash-provider.so

cc -shared -fPIC -Wall -Wextra -O2 \
    -I "$ABI_HEADER_DIR" \
    abi-mismatch-provider.c \
    -o libabi-mismatch-provider.so

echo "built: $(pwd)/libexample-provider.so"
echo "built: $(pwd)/libcrash-provider.so"
echo "built: $(pwd)/libabi-mismatch-provider.so"
