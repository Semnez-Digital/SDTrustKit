# SDTrustKit Swift Package

Swift package for the SDTrustKit Rust PDF validation core. The Swift layer owns
options JSON encoding, FFI memory handling, and report decoding; validation runs
inside the Rust core linked through `CSDTrustKit.xcframework`.

Current version: `1.0.0`.

`1.0.0` is the first public release line. `ValidationReport` and
`SignatureReport` include `padesLevel` and `preservation` fields.

## Use From An App

Add this package directory as a local or Git Swift package dependency:

```text
swift/SDTrustKit
```

Then link the `SDTrustKit` product from the app target. The package links the
binary `CSDTrustKit` target internally; app targets should import only
`SDTrustKit`.

```swift
import SDTrustKit

let verifier = try SDTrustKit()
let report = try verifier.verifyPDF(pdfData)
```

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

## Current Scope

- calls `sd_trust_kit_verify_pdf_json`
- calls `sd_trust_kit_verify_pdf_with_options_json`
- calls `sd_trust_kit_verify_pdf_including_revocation_with_options_json`
- encodes caller-owned trust anchors, timestamp pins, and CRL cache entries
- decodes the Rust `ValidationReport` JSON into Swift DTOs
- surfaces `padesLevel` and `preservation` so UI code can explain Basic,
  Timestamped, Long-term, and Archive profiles without exposing low-level
  validation steps
- compares one corpus PDF against the Rust CLI output when the sibling reference
  corpus is present
