/*
 * Deliberately faulty Model O-provider, used only to *demonstrate* (not
 * merely assert) this model's defining trade-off: a bug in an in-process
 * provider crashes Nix's own process, unlike Model O-process's spawned
 * helper, where a crashing helper produces a clean, catchable failure.
 *
 * `verify` dereferences a null pointer unconditionally. This is
 * intentional test fixture code, never to be used as a real provider.
 */

#include "signature-provider-abi.h"

static int crash_verify(
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
    volatile int * bad = (volatile int *) 0;
    return *bad; /* SIGSEGV, inside the caller's (Nix's) process */
}

static const NixSignatureProviderV1 provider = {
    .abi_version = NIX_SIGNATURE_PROVIDER_ABI_VERSION,
    .verify = crash_verify,
};

const NixSignatureProviderV1 * nix_signature_provider_v1(void)
{
    return &provider;
}
