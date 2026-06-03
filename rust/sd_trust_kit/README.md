# SDTrustKit Rust Core

Portable Rust validation core for PAdES/PDF signature verification. The Swift
and Kotlin packages wrap this crate for app integration while keeping validation
behavior shared across platforms.

Current version: `1.0.3`.

`1.0.3` includes signer-chain validity hardening, PDF timestamp parser guardrails, and the
optional Android JNI bridge. Serialized reports include `padesLevel` and
`preservation` fields on the top-level `ValidationReport` and each document
`SignatureReport`.

## Scope

The core is intentionally offline and deterministic:

- Parse PDF signature dictionaries and `/ByteRange`
- Parse CMS `SignedData`
- Validate `messageDigest`
- Verify CMS signatures for RSA PKCS#1 v1.5, RSA-PSS, and ECDSA algorithms
- Extract signer and certificate metadata
- Validate RFC 3161 timestamp message imprints and TSA signatures
- Evaluate pinned offline anchors where enough chain data is available
- Load caller-owned trust fixtures for deterministic parity and debug runs
- Evaluate signer revocation from caller-owned CRL/OCSP cache entries and
  embedded PAdES OCSP evidence in CMS/adbe archival attributes, CMS revocation
  values, `/DSS`, and `/VRI` dictionaries

Network-backed revocation refresh and EU trusted-list refresh remain
wrapper/application responsibilities. The core accepts caller-owned trust
anchors, timestamp pins, EU trusted-list cache snapshots, and deterministic CRL
and OCSP cache entries. Embedded OCSP tokens are validated as document evidence,
not as live cache responses, and are matched cryptographically to the signer
certificate before they can satisfy revocation.

## Test

Run from this directory once Rust is installed:

```sh
cargo test
```

## CLI

For local inspection, the crate builds a small JSON-report CLI:

```sh
cargo run --bin sd-trust-validate -- --pretty /path/to/file.pdf
cargo run --bin sd-trust-validate -- --offline-fixtures tests/fixtures /path/to/file.pdf
cargo run --bin sd-trust-validate -- --full-fixtures tests/fixtures /path/to/file.pdf
```

## C ABI

The C ABI is available for Swift and other native wrapper prototypes:

```c
#include "include/sd_trust_kit.h"

char *json = sd_trust_kit_verify_pdf_json(pdf_bytes, pdf_len);
sd_trust_kit_free_string(json);
```

Use `sd_trust_kit_verify_pdf_including_revocation_with_options_json` when a
wrapper has deterministic CRL/OCSP cache entries to pass into the core. The same
path also evaluates OCSP evidence already embedded in PAdES PDFs.

## Android JNI

Build or check the JNI bridge with:

```sh
cargo check --features android-jni
```

Android packaging is handled by `../../scripts/build_android_jni_libs.sh`, which
uses `cargo-ndk` to produce `.so` files for the Android library module.

## Build

Build the native library with:

```sh
cargo build --release
```

Build the Apple XCFramework used by SwiftPM with:

```sh
../../scripts/build_xcframework.sh
```

Distribution notes live in `../../docs/xcframework-distribution.md`.
