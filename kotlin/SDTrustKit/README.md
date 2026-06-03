# SDTrustKit Android

Kotlin Android bridge for the SDTrustKit Rust PDF validation core. The Android
module mirrors the Swift package: it JSON-encodes caller-owned validation
options, calls the Rust core through JNI, and decodes the Rust
`ValidationReport` JSON into Kotlin DTOs.

Current version: `1.0.2`.

## Installation

Add `kotlin/SDTrustKit` as an included build or publish the `:sdtrustkit`
Android library module through your usual artifact flow.

The app must package `libsd_trust_kit.so` for the Android ABIs it supports. Use
the repository build script to generate those libraries from the Rust core.

## Build Native Libraries

Install the Android NDK and `cargo-ndk`, then build the JNI libraries from the
repository root:

```sh
cargo install cargo-ndk
export ANDROID_NDK_HOME=/path/to/android-ndk
scripts/build_android_jni_libs.sh
```

The script writes:

```text
kotlin/SDTrustKit/sdtrustkit/src/main/jniLibs/
  arm64-v8a/libsd_trust_kit.so
  armeabi-v7a/libsd_trust_kit.so
  x86/libsd_trust_kit.so
  x86_64/libsd_trust_kit.so
```

## Usage

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
)

val report = validator.verifyPdf(pdfBytes, options)
```

With deterministic revocation evidence:

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
    ocspCacheEntries = listOf(
        OcspCacheEntry.fromUrl(
            url = "https://example.com/ocsp",
            validUntilUnixSeconds = 1_779_530_582.0,
            der = ocspResponseDer,
        ),
    ),
)

val report = validator.verifyPdfIncludingRevocation(
    pdf = pdfBytes,
    verificationOptions = options,
    revocationOptions = revocation,
)
```

## Trust And Network Policy

The native library name is `sd_trust_kit`; Kotlin loads it with
`System.loadLibrary("sd_trust_kit")`.

SDTrustKit does not perform live network fetching in the Rust core. Android apps
should own trust-list refresh, CRL/OCSP fetch, and pinning policy, then pass
deterministic trust/revocation material through `VerificationOptions` and
`RevocationOptions`. PAdES OCSP evidence embedded in CMS/adbe archival values,
CMS revocation values, `/DSS`, or `/VRI` dictionaries is evaluated by the core
without an external OCSP cache entry.

`ValidationReport.verdict` should drive badge color. `preservation.label` should
drive preservation text such as Basic, Timestamped, Long-term, or Archive.

## Test

After `jniLibs` have been built:

```sh
cd kotlin/SDTrustKit
./gradlew test
```
