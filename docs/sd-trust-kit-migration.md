# SDTrustKit Migration Notes

Current release: `1.0.1`.

`1.0.1` includes signer-validity hardening and PDF parser guardrails.
`ValidationReport` and document
`SignatureReport` include `padesLevel` and `preservation` fields in the Rust
JSON and Swift DTOs.

The Rust core lives in `rust/sd_trust_kit` and exposes the phase-1
entry point:

```rust
pub fn verify_pdf(pdf: &[u8]) -> ValidationReport;
pub fn verify_pdf_with_options(pdf: &[u8], options: &VerificationOptions) -> ValidationReport;
pub fn verify_pdf_including_revocation_with_options(
    pdf: &[u8],
    options: &VerificationOptions,
    revocation: &RevocationOptions,
) -> ValidationReport;
```

`verify_pdf` is deterministic and does not embed CEI, TSA, DigiCert, platform,
or EU trusted-list pins. Trust material is supplied from outside the core through
`VerificationOptions`:

```rust
pub struct VerificationOptions {
    pub signer_trust_anchors: Vec<Vec<u8>>,
    pub signer_trust_anchor_sets: Vec<TimedTrustAnchorSet>,
    pub timestamp_trust_anchors: Vec<Vec<u8>>,
    pub timestamp_trust_anchor_sets: Vec<TimedTrustAnchorSet>,
    pub timestamp_certificate_sha256_pins: Vec<String>,
}
```

Test fixtures under `rust/sd_trust_kit/tests/fixtures` model three
caller-owned trust sources:

- `app_trust_anchors`: SD-managed RO CEI MAI Root-CA and STS ROOT G2 DER
  certificates.
- `app_trust_pins`: SD-managed timestamp certificate SHA-256 pins.
- `eu_trusted_list`: Swift's checked-in EU trusted-list cache snapshot, decoded
  as Apple reference-time dates and converted to date-filtered signer/TSA
  anchors.
- `crl_cache`: Swift's checked-in CRL cache JSON fixtures, keyed by the
  SHA-256 of each normalized CRL URL.
- `system_trust_anchors`: the minimal macOS roots needed to reproduce the
  current Swift offline baseline deterministically.

The CEISign app currently consumes `Packages/CEISignPDFValidation` and its
`PdfVerifier` surface. Keep that package as the app-facing adapter during the
first integration so CEISign UI code can keep importing `CEISignPDFValidation`
while validation behavior moves to SDTrustKit underneath it.

## Wrapper Shape

iOS, Android, and Windows should call the same Rust core. Platform code should
be thin adapters that:

- pass PDF bytes to `verify_pdf_with_options`
- provide app-managed trust anchors or certificate pins when trust evaluation is
  desired
- serialize `ValidationReport` to JSON or map it to native DTOs
- render the existing verdict, standards, signer, certificate, and step fields

The first C ABI is intentionally string-based. The Rust core owns validation
behavior, while platform wrappers own how PDF bytes and trust material are
loaded:

```c
char *sd_trust_kit_verify_pdf_json(const uint8_t *pdf, size_t len);
char *sd_trust_kit_verify_pdf_with_options_json(
    const uint8_t *pdf,
    size_t len,
    const char *options_json
);
char *sd_trust_kit_verify_pdf_including_revocation_with_options_json(
    const uint8_t *pdf,
    size_t len,
    const char *verification_options_json,
    const char *revocation_options_json
);
void sd_trust_kit_free_string(char *ptr);
```

Kotlin, Swift, and C# wrappers can then own memory safely while keeping
validation behavior inside Rust. `options_json` uses base64-encoded DER trust
anchors and timestamp pins so app/platform pinning stays outside the core:

```json
{
  "signerTrustAnchorsDerBase64": ["..."],
  "signerTrustAnchorSets": [
    {
      "validFromUnixSeconds": 1700000000.0,
      "validUntilUnixSeconds": 1800000000.0,
      "anchorsDerBase64": ["..."]
    }
  ],
  "timestampTrustAnchorsDerBase64": ["..."],
  "timestampTrustAnchorSets": [
    {
      "validFromUnixSeconds": 1700000000.0,
      "validUntilUnixSeconds": 1800000000.0,
      "anchorsDerBase64": ["..."]
    }
  ],
  "timestampCertificateSha256Pins": ["..."]
}
```

If the FFI layer cannot decode input, it returns JSON in the shape
`{"error":{"code":"...","message":"..."}}` instead of unwinding across the C
boundary. The checked-in header lives at
`rust/sd_trust_kit/include/sd_trust_kit.h`.

Revocation-aware FFI remains deterministic and offline. Wrappers pass cached CRL
entries explicitly:

```json
{
  "nowUnixSeconds": 1779530582.0,
  "crlCacheEntries": [
    {
      "url": "https://example.com/signers.crl",
      "cacheKeySha256": "optional-precomputed-cache-key",
      "validUntilUnixSeconds": 1779530582.0,
      "derBase64": "..."
    }
  ]
}
```

`url` is normalized and hashed the same way as the Rust verifier. A wrapper may
provide `cacheKeySha256` instead when it already owns a cache keyed by normalized
CRL URL hash. `nowUnixSeconds` is required when `crlCacheEntries` is non-empty
so CRL expiration checks are deterministic.

## Swift Package And XCFramework

The Swift package lives in `swift/SDTrustKit`. It links the packaged
`CSDTrustKit.xcframework`, calls the exported C ABI, frees returned strings with
`sd_trust_kit_free_string`, and decodes the Rust `ValidationReport` JSON into
Swift DTOs.

The XCFramework supports iOS device, iOS simulator, and macOS:

- `ios-arm64`
- `ios-arm64_x86_64-simulator`
- `macos-arm64_x86_64`

Rebuild it from the repository root:

```sh
scripts/build_xcframework.sh
```

Build and test the Swift package from the package directory:

```sh
swift test
```

The package also supports local dylib experiments when compiled without
`SD_TRUST_KIT_STATIC`; pass `libraryURL:` or set `SD_TRUST_KIT_DYLIB`.

The Swift tests cover core verification, caller-owned trust options,
revocation-cache options, and a corpus smoke test that compares Swift-decoded
output against the Rust CLI for `0001.pdf` when the sibling reference corpus is
available.

For CEISign, add `swift/SDTrustKit` as a package dependency and initially make
`CEISignPDFValidation` depend on `SDTrustKit`. Map the existing `PdfVerifier`
types and trust-provider hooks to `ValidationReport`, `VerificationOptions`,
and `RevocationOptions` inside that adapter before changing app imports.

Keep network fetches, CRL refresh, EU trusted-list refresh, and pinned trust
ownership in CEISign. SDTrustKit consumes caller-owned trust anchors, timestamp
pins, EU trusted-list cache snapshots, and cached CRLs; it does not fetch or
pin remote material itself.

## Preservation Labels And Badge Policy

`ValidationReport` and every document `SignatureReport` expose two UI-oriented
fields:

- `padesLevel`: `unknown`, `baselineB`, `baselineT`, `baselineLT`, or
  `baselineLTA`.
- `preservation`: a structured label/detail pair with levels `unknown`,
  `basic`, `timestamped`, `longTerm`, or `archival`.

These fields describe preservation strength, not the badge color by themselves.
CEISign should keep badge color tied to `verdict` and `standards`:

- Green: the signature is valid under the evidence CEISign supplied.
- Yellow: the document signature is cryptographically intact, but trust,
  timestamp, or revocation evidence is incomplete.
- Red: the document was modified, the digest/signature does not match, the
  signer was revoked before signing, or the signature/container is malformed.

Recommended user-facing labels:

- Basic: PAdES-B-B. The document signature is intact, but no trusted timestamp
  was validated. This can be green when the signature is valid now, but the UI
  should explain that long-term validity may require fresh evidence.
- Timestamped: PAdES-B-T. A trusted timestamp proves the signature existed at
  the timestamp time.
- Long-term: PAdES-B-LT. Trusted timestamp and validation evidence are
  available for long-term validation.
- Archive: PAdES-B-LTA. Long-term validation evidence is protected by a trusted
  document timestamp.

The classifier is intentionally conservative. It promotes to B-T only when the
signature timestamp imprint, signature, EKU, and timestamp chain all validate.
It promotes to B-LT only when B-T evidence is present, validation-data-only PDF
updates are detected, and signer revocation evidence validates. It promotes the
top-level report to B-LTA only when a trusted document timestamp is also present.

For CEISign UI purposes, treat `padesLevel` and `preservation` as explanatory
metadata. A valid PAdES-B-B signature may receive a green badge because the
signature is valid under the supplied evidence, while its preservation label
should remain `Basic`. A valid PAdES-B-T signature may also receive a green
badge, with the preservation label `Timestamped`.

## Local CLI

The crate includes a deliberately small debug binary that prints the serialized
`ValidationReport` JSON for one PDF:

```sh
cargo run --bin sd-trust-validate -- --pretty /path/to/file.pdf
```

Fixture modes let developers reproduce the same deterministic trust inputs used
by the Rust corpus tests without moving trust pins into the core:

```sh
cargo run --bin sd-trust-validate -- \
  --offline-fixtures tests/fixtures \
  /path/to/signed.pdf

cargo run --bin sd-trust-validate -- \
  --full-fixtures tests/fixtures \
  /path/to/signed.pdf
```

`--offline-fixtures` supplies only the deterministic system roots used by the
offline baseline. `--full-fixtures` supplies SD app anchors, timestamp
pins, the cached EU trusted list, and the cached CRLs, then runs the
revocation-aware verifier.

## Parity Status

| Check | Status | Notes |
| --- | --- | --- |
| Report model and standards mapping | Implemented | Mirrors Swift step-first failure/warning projection. |
| PDF `/ByteRange` discovery | Implemented | Scans outside streams and keeps document timestamps. |
| `/ByteRange` coverage and bounds | Implemented | Includes validation-data-only tail detection. |
| CMS `SignedData` parsing | Implemented | Custom parser preserves signed/unsigned attribute bytes. |
| `messageDigest` validation | Implemented | SHA-1/SHA-256/SHA-384/SHA-512. |
| CMS signature verification | Implemented | RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256/P-384 prehash verification. |
| Signer certificate selection | Implemented | Matches `SignerInfo` serial or subject key identifier. |
| Certificate metadata | Implemented | Common name, summaries, serial, SHA-1/SHA-256 fingerprints. |
| External signer trust anchors | Implemented | Manual offline chain to caller-supplied anchors; no anchors are embedded in core. Covered by fixture-backed options tests. |
| RFC 3161 timestamp token | Implemented | Message imprint, TSA signature, EKU, caller-supplied timestamp anchors/pins. Generic anchor/pin behavior is unit-tested; the offline corpus has no trusted timestamp-pin case. |
| EU trusted-list cache | Implemented offline | Parses the Swift `trusted-certificates-v2.json` fixture, applies matching status/date/service filters, and feeds signer/TSA timed anchors into `VerificationOptions`. Network refresh is still pending. |
| Platform system trust | Pending | Needs cross-platform trust abstraction. |
| User-supplied anchors | Implemented | Available through `VerificationOptions`; wrappers own trust material. |
| CRL revocation | Implemented offline | Deterministic cache-backed signer CRL checks are implemented for checked-in fixtures, including CRL signature authentication and revoked-serial lookup. Network fetch/refresh is still pending. |
| FFI | Initial ABI implemented | String-based C ABI returns report JSON, accepts caller-supplied trust anchors/pins and deterministic CRL cache entries via JSON, and includes ownership/error tests. Network refresh FFI remains pending. |
| Swift wrapper prototype | Implemented | Thin `dlopen` wrapper calls the C ABI and decodes reports; one corpus smoke test compares against the Rust CLI. |

## Full Baseline Harness

The full network-baseline comparison is wired as an ignored Rust test so normal
`cargo test` stays green while remaining parity gaps are triaged:

```sh
cargo test pdf_corpus_matches_swift_full_network_baseline -- --ignored --nocapture
```

As of May 26, 2026, that harness passes against
`pdfvalidation-full-baseline.json` using the checked-in EU trusted-list cache,
CRL cache, app trust fixtures, and system trust fixtures. The Rust harness keeps
network refresh disabled; all revocation and trusted-list inputs are loaded
from deterministic fixtures.

## Phase-1 Baseline Normalizations

- Swift's current offline baseline includes platform trust-store behavior for a
  small number of public certificates. The Rust core performs portable chain
  checks only against trust anchors supplied from outside the core. The Rust
  corpus test supplies the minimal macOS system-root anchors needed by the
  checked-in Swift offline baseline from `tests/fixtures/system_trust_anchors`.
- The corpus test normalizes only the legacy Swift diagnostic strings that name
  app/platform trust sources. Step kinds, statuses, standards indication and
  sub-indication, signer metadata, and certificate-chain metadata are still
  compared directly.
- The checked-in Swift baseline is stale for `0122.pdf`, `0124.pdf`,
  `0131.pdf`, and `0141.pdf`. Current Swift source reports "document modified
  after signing" for those exact file hashes, so the Rust corpus test normalizes
  the older baseline entries before comparison.
- No network access is used by phase 1 or by the current full-baseline harness.
  EU trusted-list and CRL inputs are deterministic and fixture-backed.
