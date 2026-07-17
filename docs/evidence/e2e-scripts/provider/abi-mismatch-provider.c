/*
 * Deliberately declares an incompatible ABI version, to test that Nix's
 * loader treats a version mismatch as a hard load-time error rather
 * than calling a provider with a calling convention it does not
 * actually implement.
 */

#include "signature-provider-abi.h"

static int unreachable_verify(
    const char * algorithm,
    const uint8_t * key_bytes, size_t key_len,
    const uint8_t * message_bytes, size_t message_len,
    const uint8_t * signature_bytes, size_t signature_len)
{
    (void) algorithm;
    (void) key_bytes;
    (void) key_len;
    (void) message_bytes;
    (void) message_len;
    (void) signature_bytes;
    (void) signature_len;
    return NIX_SIG_ERROR;
}

static const NixSignatureProviderV1 provider = {
    .abi_version = 999, /* deliberately wrong */
    .verify = unreachable_verify,
};

const NixSignatureProviderV1 * nix_signature_provider_v1(void)
{
    return &provider;
}
