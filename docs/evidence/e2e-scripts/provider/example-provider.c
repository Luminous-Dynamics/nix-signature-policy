/*
 * Example Model O-provider implementation: a minimal, real, in-process
 * signature verifier using libsodium directly, implementing the C ABI
 * in signature-provider-abi.h.
 *
 * Deliberately scoped to Ed25519 only, matching the O-provider stop/go
 * review's "implementation can stay small" criterion and the real
 * #14451 thread comment (xokdvium) this model is grounded in, which
 * scoped its own PKCS#11 suggestion to "building on top of the existing
 * signature formats" -- verification, not evidence normalization or
 * multi-algorithm negotiation. Any other algorithm name returns
 * NIX_SIG_ERROR, not a silent "invalid", so a caller cannot mistake
 * "this provider doesn't handle ML-DSA" for "this ML-DSA signature is
 * bad".
 *
 * This is example/experimental code for the authorization-boundary
 * comparison, not a production Nix component.
 */

#include "signature-provider-abi.h"

#include <sodium.h>
#include <string.h>

static int example_verify(
    const char * algorithm,
    const uint8_t * key_bytes, size_t key_len,
    const uint8_t * message_bytes, size_t message_len,
    const uint8_t * signature_bytes, size_t signature_len)
{
    if (algorithm == NULL || strcmp(algorithm, "ed25519") != 0)
        return NIX_SIG_ERROR;

    if (key_len != crypto_sign_PUBLICKEYBYTES)
        return NIX_SIG_ERROR;

    if (signature_len != crypto_sign_BYTES)
        return NIX_SIG_ERROR;

    int rc = crypto_sign_verify_detached(signature_bytes, message_bytes, message_len, key_bytes);
    return rc == 0 ? NIX_SIG_VALID : NIX_SIG_INVALID;
}

static const NixSignatureProviderV1 provider = {
    .abi_version = NIX_SIGNATURE_PROVIDER_ABI_VERSION,
    .verify = example_verify,
};

const NixSignatureProviderV1 * nix_signature_provider_v1(void)
{
    /* sodium_init() is idempotent and safe to call on every load; a
       real provider that needs library-global init would do it here,
       once, at first load, per this ABI's "loaded once, cached for the
       process lifetime" contract. */
    (void) sodium_init();
    return &provider;
}
