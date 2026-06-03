# SDTrustKit

SDTrustKit is a portable PDF signature validation SDK built around a shared Rust
core. It validates signed PDFs and emits the same structured JSON report across
Rust, Swift, and Android integrations.

The project is designed for applications that already own trust policy,
certificate pinning, EU trusted-list refresh, CRL/OCSP refresh, and product UI.
SDTrustKit performs deterministic local validation against the PDF bytes and the
trust/revocation material supplied by the caller.

Current version: `1.0.2`

## Packages

| Package | Path | Purpose |
| --- | --- | --- |
| Rust core | `rust/sd_trust_kit` | Validation engine, C ABI, optional Android JNI exports, and `sd-trust-validate` CLI |
| Swift package | `Package.swift` | Root SwiftPM package backed by `swift/SDTrustKit/Frameworks/CSDTrustKit.xcframework` |
| Android package | `kotlin/SDTrustKit` | Kotlin Android library module backed by JNI |
| Docs | `docs` | Migration notes, XCFramework distribution notes, and fixture analysis |
| Corpus reports | `validation-corpus/performance-reports` | Offline benchmark artifacts for SDTrustKit, EU DSS, and pyHanko |

## Install With Xcode

SDTrustKit is distributed as a Swift Package through Git tags. In Xcode, choose
**File > Add Package Dependencies...** and use:

```text
https://github.com/Semnez-Digital/SDTrustKit.git
```

Recommended dependency rule:

```text
Up to Next Major Version: 1.0.2
```

Then add the `SDTrustKit` product to your app target and import it from Swift:

```swift
import SDTrustKit
```

Future updates are published by pushing the next semver tag.
In Xcode, use **File > Packages > Update to Latest Package Versions** to move to
the newest compatible `1.x` release, or edit the package requirement if you want
to pin an exact version.

## Validation Scope

The Rust core currently covers:

- PDF detection, signature dictionary discovery, AcroForm signature field
  resolution, and `/ByteRange` validation
- CMS `SignedData` parsing and `messageDigest` validation
- RSA PKCS#1 v1.5, RSA-PSS, and ECDSA signature verification
- Signer certificate extraction, validity checks, key usage checks, and
  caller-supplied trust-anchor evaluation
- RFC 3161 timestamp token parsing, message imprint checks, TSA signature
  verification, TSA EKU checks, and TSA trust evaluation
- PAdES baseline reporting for `baselineB`, `baselineT`, `baselineLT`, and
  `baselineLTA`
- Deterministic CRL cache evaluation when the caller supplies cached CRL entries
- Conservative detection for malformed or suspicious PDF signature structures,
  including out-of-bounds byte ranges, altered signed revisions, field-reference
  swaps, and orphan signature dictionaries

The core intentionally does not perform live network fetching. Applications
should fetch and cache trust lists, intermediate certificates, CRLs, OCSP
responses, and timestamp policy material outside SDTrustKit, then pass the
resulting deterministic inputs into validation.

## Report Model

All entry points return a `ValidationReport` with the same schema. The top-level
report and each document `SignatureReport` include:

- `verdict`: `valid`, `warning`, `inconclusive`, `invalid`, `noSignatures`, or
  `error`
- `standards.indication`: `passed`, `failed`, or `needsEvidence`
- `standards.subIndication`: a stable reason such as
  `documentHashMismatch`, `certificateChainIssue`, or
  `revocationEvidenceUnavailable`
- `steps`: ordered validation steps with `ok`, `warn`, `fail`, or `skip`
  statuses
- `signerName`, `signerNames`, `signingTime`, certificate details, timestamp
  details, byte range information, and document timestamp reports
- `padesLevel`: `unknown`, `baselineB`, `baselineT`, `baselineLT`, or
  `baselineLTA`
- `preservation`: a UI-oriented preservation assessment with labels such as
  `Basic`, `Timestamped`, `Long-term`, and `Archive`

Use `verdict` and `standards` for badge color and policy decisions. Use
`padesLevel` and `preservation` to explain long-term validation strength.

## Rust

The Rust crate is private to this repository (`publish = false`) and builds an
`rlib`, `staticlib`, and `cdylib`.

```sh
cd rust/sd_trust_kit
cargo test
```

Programmatic entry points:

```rust
use sd_trust_kit::{
    verify_pdf,
    verify_pdf_with_options,
    verify_pdf_including_revocation_with_options,
    VerificationOptions,
    RevocationOptions,
};

let report = verify_pdf(pdf_bytes);
let report = verify_pdf_with_options(pdf_bytes, &VerificationOptions::default());
let report = verify_pdf_including_revocation_with_options(
    pdf_bytes,
    &VerificationOptions::default(),
    &RevocationOptions::default(),
);
```

The CLI emits the same JSON report:

```sh
cargo run --bin sd-trust-validate -- --pretty /path/to/file.pdf
cargo run --bin sd-trust-validate -- --offline-fixtures tests/fixtures /path/to/file.pdf
cargo run --bin sd-trust-validate -- --full-fixtures tests/fixtures /path/to/file.pdf
```

`--offline-fixtures` loads local system trust-anchor fixtures. `--full-fixtures`
loads app anchors, timestamp pins, EU trusted-list cache fixtures, system
anchors, and CRL cache fixtures.

## C ABI

The C ABI is string-based so platform wrappers can own memory and JSON decoding
without duplicating validation logic.

```c
#include "sd_trust_kit.h"

char *json = sd_trust_kit_verify_pdf_json(pdf_bytes, pdf_len);
sd_trust_kit_free_string(json);
```

Available exported functions:

- `sd_trust_kit_verify_pdf_json`
- `sd_trust_kit_verify_pdf_with_options_json`
- `sd_trust_kit_verify_pdf_including_revocation_with_options_json`
- `sd_trust_kit_free_string`

If option JSON cannot be decoded, the ABI returns:

```json
{"error":{"code":"...","message":"..."}}
```

## Swift

The Swift package supports iOS 15+ and macOS 13+. It links the bundled
`CSDTrustKit.xcframework` internally, so app targets import only `SDTrustKit`.

```swift
import SDTrustKit

let validator = try SDTrustKit()
let report = try validator.verifyPDF(pdfData)
```

With explicit trust material:

```swift
let options = VerificationOptions(
    signerTrustAnchorsDer: [rootCertificateDer],
    timestampTrustAnchorsDer: [tsaRootDer],
    timestampCertificateSha256Pins: [timestampCertificatePin]
)

let report = try validator.verifyPDF(pdfData, options: options)
```

With deterministic CRL evidence:

```swift
let revocation = RevocationOptions(
    nowUnixSeconds: 1_779_530_582,
    crlCacheEntries: [
        CrlCacheEntry(
            url: "https://example.com/intermediate.crl",
            validUntilUnixSeconds: 1_779_530_582,
            der: crlDer
        )
    ]
)

let report = try validator.verifyPDFIncludingRevocation(
    pdfData,
    verificationOptions: options,
    revocationOptions: revocation
)
```

The checked-in XCFramework contains:

- iOS device: `arm64`
- iOS simulator: `arm64`, `x86_64`
- macOS: `arm64`, `x86_64`

Rebuild it from the repository root:

```sh
scripts/build_xcframework.sh
```

## Android

The Android bridge is a Kotlin library module with namespace `com.sdtrustkit`,
minimum SDK 23, compile SDK 35, Kotlin JVM toolchain 17, and
`kotlinx-serialization-json` for report decoding.

```kotlin
import com.sdtrustkit.SDTrustKit

val validator = SDTrustKit()
val report = validator.verifyPdf(pdfBytes)
```

With explicit trust material:

```kotlin
val options = VerificationOptions.fromDer(
    signerTrustAnchorsDer = listOf(rootCertificateDer),
    timestampTrustAnchorsDer = listOf(tsaRootDer),
    timestampCertificateSha256Pins = listOf(timestampCertificatePin),
)

val report = validator.verifyPdf(pdfBytes, options)
```

With deterministic CRL evidence:

```kotlin
val revocation = RevocationOptions(
    nowUnixSeconds = 1_779_530_582.0,
    crlCacheEntries = listOf(
        CrlCacheEntry.fromUrl(
            url = "https://example.com/intermediate.crl",
            validUntilUnixSeconds = 1_779_530_582.0,
            der = crlDer,
        ),
    ),
)

val report = validator.verifyPdfIncludingRevocation(
    pdf = pdfBytes,
    verificationOptions = options,
    revocationOptions = revocation,
)
```

Build Android JNI libraries after installing the Android NDK and `cargo-ndk`:

```sh
cargo install cargo-ndk
export ANDROID_NDK_HOME=/path/to/android-ndk
scripts/build_android_jni_libs.sh
```

The script writes `libsd_trust_kit.so` for `armeabi-v7a`, `arm64-v8a`, `x86`,
and `x86_64` under `kotlin/SDTrustKit/sdtrustkit/src/main/jniLibs`.

## Build And Test

Rust:

```sh
cd rust/sd_trust_kit
cargo fmt -- --check
cargo test
cargo clippy --all-targets --features android-jni -- -D warnings
```

Swift:

```sh
cd swift/SDTrustKit
swift test
```

Android, after JNI libraries are built:

```sh
cd kotlin/SDTrustKit
./gradlew test
```

## Benchmark Corpus

The checked-in performance report compares offline validation on a
symlink-expanded corpus of 1,665 PDFs across SDTrustKit, EU DSS, and pyHanko.
The report is an engineering benchmark, not a conformance certification.

Current artifacts:

- `validation-corpus/performance-reports/latest-pdf-benchmark.html`
- `validation-corpus/performance-reports/2026-05-28-public-offline-pdf-validation/report.html`
- `validation-corpus/performance-reports/2026-05-28-public-offline-pdf-validation/summary.json`

The benchmark disables or avoids network access so timing and result categories
reflect local validation behavior.

## Repository Layout

```text
docs/                 Migration, distribution, and fixture notes
kotlin/SDTrustKit/    Kotlin Android bridge
rust/sd_trust_kit/    Rust core, CLI, FFI, JNI feature, and tests
scripts/              XCFramework, Android JNI, fixture, and benchmark helpers
swift/SDTrustKit/     SwiftPM package and CSDTrustKit.xcframework
validation-corpus/    Local corpus data and benchmark reports
```

## License And Distribution

SDTrustKit is licensed under the GNU Lesser General Public License, version 2.1
or later (`LGPL-2.1-or-later`), matching the DSS project license family.

Copyright (C) 2026 Backup Experts SRL.

See `LICENSE` for the full LGPL 2.1 text and `NOTICE` for the SDTrustKit
copyright and license notice. The Rust crate remains `publish = false`; the
Swift package is distributed through Git tags and the Android bridge is kept in
this repository for app/library integration.
