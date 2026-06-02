# SDTrustKit Swift Package

Swift Package Manager wrapper for the SDTrustKit Rust PDF validation core. The
Swift layer owns option encoding, FFI memory handling, and report decoding while
validation runs inside the bundled `CSDTrustKit.xcframework`.

Current version: `1.0.1`.

`1.0.1` includes signer-validity hardening and PDF parser guardrails.
`ValidationReport` and `SignatureReport` include `padesLevel` and
`preservation` fields.

## Installation

Add this package directory as a local or Git Swift package dependency:

```text
swift/SDTrustKit
```

Then link the `SDTrustKit` product from the app target. The package links
`CSDTrustKit` internally; app targets should import only `SDTrustKit`.

## Usage

```swift
import SDTrustKit

let verifier = try SDTrustKit()
let report = try verifier.verifyPDF(pdfData)
```

With explicit trust material:

```swift
let options = VerificationOptions(
    signerTrustAnchorsDer: [rootCertificateDer],
    timestampTrustAnchorsDer: [tsaRootDer]
)

let report = try verifier.verifyPDF(pdfData, options: options)
```

## Report Model

The report separates validation outcome from preservation level:

- `verdict`: whether the signature is valid with the supplied evidence.
- `padesLevel`: detected PAdES baseline level, such as `baselineB` or
  `baselineT`.
- `preservation.label`: user-facing preservation label, such as `Basic`,
  `Timestamped`, `Long-term`, or `Archive`.

Use `verdict` for badge color and `preservation.label` for preservation text.
A valid PAdES-B-B signature can be shown as valid while still carrying the
`Basic` preservation label.

Recommended app copy:

- `Basic`: valid basic signature; long-term validity may require fresh
  certificate/revocation evidence.
- `Timestamped`: trusted time proves the signature existed at the timestamp
  time.
- `Long-term`: timestamp and validation evidence are available for future
  validation.
- `Archive`: long-term evidence is protected by a trusted document timestamp.

The packaged XCFramework supports:

- iOS device: `arm64`
- iOS simulator: `arm64`, `x86_64`
- macOS: `arm64`, `x86_64`

## Rebuild The XCFramework

Install the Rust Apple targets, then run the repository script:

```sh
../../scripts/build_xcframework.sh
```

See `../../docs/xcframework-distribution.md` for the full target list and CEISign
adapter notes.

## Test

```sh
swift test
```

For local dylib experiments, compile without `SD_TRUST_KIT_STATIC` and pass
`libraryURL:` or set `SD_TRUST_KIT_DYLIB` in the environment.

## API Coverage

- Calls `sd_trust_kit_verify_pdf_json`
- Calls `sd_trust_kit_verify_pdf_with_options_json`
- Calls `sd_trust_kit_verify_pdf_including_revocation_with_options_json`
- Encodes caller-owned trust anchors, timestamp pins, and CRL cache entries
- Decodes the Rust `ValidationReport` JSON into Swift DTOs
- Surfaces `padesLevel` and `preservation` so UI code can explain Basic,
  Timestamped, Long-term, and Archive profiles without exposing low-level
  validation steps
- Compares one corpus PDF against the Rust CLI output when the sibling reference
  corpus is present
