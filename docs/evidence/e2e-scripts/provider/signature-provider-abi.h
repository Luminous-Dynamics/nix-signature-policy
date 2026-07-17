/*
 * A minimal, versioned, PKCS#11-*inspired* (not compliant) verification-
 * only ABI for in-process Nix signature observation providers.
 *
 * Scope: raw cryptographic verification of a single (key, message,
 * signature) triple, nothing more. Evidence normalization, key/slot/
 * session management, multi-mechanism negotiation, and policy are all
 * explicitly out of scope -- see the O-provider stop/go review in the
 * authorization-boundary-architecture comparison this header was built
 * for, which grounds this design in a real Nix issue #14451 thread
 * comment (`xokdvium`, proposing a PKCS#11-shaped module) while
 * deliberately not claiming PKCS#11 conformance.
 *
 * This is a plain C header on purpose: it is the ABI boundary between
 * Nix (a C++ process) and an independently compiled, independently
 * authored `dlopen`'d shared library, which may not be C++ at all.
 */

#ifndef NIX_SIGNATURE_PROVIDER_ABI_H
#define NIX_SIGNATURE_PROVIDER_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NIX_SIGNATURE_PROVIDER_ABI_VERSION 1u

/* Return values for `verify`. */
#define NIX_SIG_VALID 1
#define NIX_SIG_INVALID 0
#define NIX_SIG_ERROR (-1)

typedef struct NixSignatureProviderV1
{
    /*
     * Must equal NIX_SIGNATURE_PROVIDER_ABI_VERSION. The caller checks
     * this before dereferencing `verify`, so a provider built against a
     * future, incompatible ABI version fails loudly at load time
     * instead of being called with a mismatched calling convention.
     */
    uint32_t abi_version;

    /*
     * Verify a single detached signature against a single already-
     * decoded public key.
     *
     * `algorithm` is one of Nix's frozen wire algorithm names
     * ("ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ecdsa-p384"),
     * NUL-terminated. A provider that does not support the given
     * algorithm must return NIX_SIG_ERROR, not silently treat it as
     * invalid -- the caller distinguishes "this key/signature pair
     * does not match" from "this provider cannot evaluate this input
     * at all", and a `NIX_SIG_ERROR` is a hard failure of the whole
     * admission decision, never silently downgraded to "not valid".
     *
     * `key_bytes`/`message_bytes`/`signature_bytes` are raw
     * (non-Base64, non-PEM) bytes; the caller owns them and they are
     * valid only for the duration of this call.
     *
     * Returns NIX_SIG_VALID, NIX_SIG_INVALID, or NIX_SIG_ERROR. Must
     * not throw (this is a C ABI -- a C++ implementation must catch
     * every exception at this boundary), must not retain any pointer
     * argument past the call, and must be safe to call repeatedly,
     * synchronously, from the single thread that loaded the library.
     */
    int (*verify)(
        const char * algorithm,
        const uint8_t * key_bytes,
        size_t key_len,
        const uint8_t * message_bytes,
        size_t message_len,
        const uint8_t * signature_bytes,
        size_t signature_len);
} NixSignatureProviderV1;

/*
 * Fixed entry-point symbol every provider shared library must export.
 * Must return a pointer to a statically allocated `NixSignatureProviderV1`,
 * valid for the remaining lifetime of the process once the library is
 * loaded (the caller never `dlclose`s a loaded provider -- see the
 * lifetime-semantics discussion in the stop/go review).
 */
const NixSignatureProviderV1 * nix_signature_provider_v1(void);

#ifdef __cplusplus
}
#endif

#endif /* NIX_SIGNATURE_PROVIDER_ABI_H */
