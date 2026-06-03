#ifndef SD_TRUST_KIT_H
#define SD_TRUST_KIT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns a newly allocated UTF-8 JSON ValidationReport string.
// Free the returned pointer with sd_trust_kit_free_string.
char *sd_trust_kit_verify_pdf_json(const uint8_t *pdf, size_t pdf_len);

// Returns a newly allocated UTF-8 JSON ValidationReport string using
// caller-supplied trust material. options_json may be NULL for defaults.
//
// Supported options_json shape:
// {
//   "signerTrustAnchorsDerBase64": ["..."],
//   "signerTrustAnchorSets": [
//     {
//       "validFromUnixSeconds": 1700000000.0,
//       "validUntilUnixSeconds": 1800000000.0,
//       "anchorsDerBase64": ["..."]
//     }
//   ],
//   "timestampTrustAnchorsDerBase64": ["..."],
//   "timestampTrustAnchorSets": [
//     {
//       "validFromUnixSeconds": 1700000000.0,
//       "validUntilUnixSeconds": 1800000000.0,
//       "anchorsDerBase64": ["..."]
//     }
//   ],
//   "timestampCertificateSha256Pins": ["..."]
// }
//
// If input decoding fails, the returned JSON has this shape:
// {"error":{"code":"...","message":"..."}}
char *sd_trust_kit_verify_pdf_with_options_json(const uint8_t *pdf,
                                      size_t pdf_len,
                                      const char *options_json);

// Runs the revocation-aware verifier using caller-supplied trust material and
// deterministic CRL/OCSP cache entries. verification_options_json and
// revocation_options_json may be NULL for defaults.
//
// Supported revocation_options_json shape:
// {
//   "nowUnixSeconds": 1779530582.0,
//   "crlCacheEntries": [
//     {
//       "url": "https://example.com/signers.crl",
//       "cacheKeySha256": "optional-precomputed-cache-key",
//       "validUntilUnixSeconds": 1779530582.0,
//       "derBase64": "..."
//     }
//   ],
//   "ocspCacheEntries": [
//     {
//       "url": "https://example.com/ocsp",
//       "cacheKeySha256": "optional-precomputed-cache-key",
//       "validUntilUnixSeconds": 1779530582.0,
//       "derBase64": "..."
//     }
//   ]
// }
//
// nowUnixSeconds is required when crlCacheEntries or ocspCacheEntries is non-empty.
char *sd_trust_kit_verify_pdf_including_revocation_with_options_json(
    const uint8_t *pdf,
    size_t pdf_len,
    const char *verification_options_json,
    const char *revocation_options_json);

// Frees strings returned by this library. Passing NULL is allowed.
void sd_trust_kit_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
