# XCFramework Distribution

SDTrustKit ships a Swift package backed by a static Rust XCFramework:

- Current version: `1.0.3`
- Swift target: `SDTrustKit`
- C binary target: `CSDTrustKit`
- Artifact path: `swift/SDTrustKit/Frameworks/CSDTrustKit.xcframework`

`1.0.3` includes signer-chain validity hardening, PDF timestamp parser guardrails, and OCSP revocation support.
`ValidationReport` and document
`SignatureReport` include `padesLevel` and `preservation` fields so apps can
show PAdES preservation labels separately from the validation verdict.

The XCFramework contains these slices:

- iOS device: `arm64`
- iOS simulator: `arm64`, `x86_64`
- macOS: `arm64`, `x86_64`

## Rebuild

Install Rust with `rustup`, then install the Apple targets:

```sh
rustup target add \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios \
  aarch64-apple-darwin \
  x86_64-apple-darwin
```

Build the artifact from the repository root:

```sh
scripts/build_xcframework.sh
```

The script writes `swift/SDTrustKit/Frameworks/CSDTrustKit.xcframework`.

## SwiftPM Integration

Add `swift/SDTrustKit` as a local or Git package dependency and link the
`SDTrustKit` product. The Swift package depends on the binary `CSDTrustKit`
target internally, so app targets should not link `CSDTrustKit` directly.

For CEISign, the lowest-risk migration is to keep the existing
`CEISignPDFValidation` module as an adapter initially:

1. Add `SDTrustKit` to
   `CEISign/Packages/CEISignPDFValidation/Package.swift`:

   ```swift
   dependencies: [
     .package(name: "SDTrustKit", path: "../../../SDTrustKit/swift/SDTrustKit"),
   ]
   ```

2. Add the product to the existing target dependencies:

   ```swift
   .target(
     name: "CEISignPDFValidation",
     dependencies: [
       .product(name: "SDTrustKit", package: "SDTrustKit"),
     ]
   )
   ```

3. Keep CEISign's `project.yml` app dependency pointed at the local
   `CEISignPDFValidation` package while the adapter is in place. That avoids
   changing the many existing `import CEISignPDFValidation` call sites.
4. Map the current `PdfVerifier.Report`, `SignatureReport`, `Step`, and
   trust-provider hooks onto `SDTrustKit.ValidationReport`.
5. Use `ValidationReport.verdict` for badge color and
   `ValidationReport.preservation.label` for the user-facing preservation label.
6. Once the app UI is no longer coupled to `PdfVerifier`, remove the adapter.

This lets the app keep importing `CEISignPDFValidation` while the validation
engine changes underneath it.

## CEISign Agent Prompt

Use this prompt when wiring SDTrustKit into CEISign:

```text
You are working in the CEISign app. Integrate SDTrustKit 1.0.3 with the smallest
possible app-facing change.

Context:
- SDTrustKit is a SwiftPM package at SDTrustKit/swift/SDTrustKit.
- It exposes the Swift product SDTrustKit, backed internally by
  CSDTrustKit.xcframework.
- CEISign currently imports Packages/CEISignPDFValidation and uses its
  PdfVerifier surface.
- Keep network fetches, CRL refresh, EU trusted-list refresh, and pinned trust
  ownership inside CEISign/CEISignPDFValidation. SDTrustKit only consumes
  caller-supplied trust anchors, timestamp pins, EU trusted-list snapshots, and
  cached CRL entries through options.

Tasks:
1. Add SDTrustKit as a dependency of the existing CEISignPDFValidation package.
2. Keep CEISign app imports unchanged at first. Make CEISignPDFValidation an
   adapter over SDTrustKit instead of rewriting UI call sites.
3. Map CEISign's existing PdfVerifier input/options/trust-provider model to
   SDTrustKit.VerificationOptions and SDTrustKit.RevocationOptions.
4. Map SDTrustKit.ValidationReport back to the CEISign report types expected by
   the current UI. Preserve existing verdict, signer, certificate, standards,
   and step semantics.
5. Surface the new preservation fields in the UI:
   - Use ValidationReport.verdict for badge color.
   - Use ValidationReport.preservation.label for the preservation text.
   - Use ValidationReport.padesLevel only for structured/debug/details UI.
6. Badge policy:
   - Green means valid with the evidence CEISign supplied.
   - Yellow means intact but trust/timestamp/revocation evidence is incomplete.
   - Red means modified, digest/signature mismatch, revoked before signing, or
     malformed.
   - PAdES-B-B can be green if the verdict is valid, but label it Basic.
   - PAdES-B-T can be green if the verdict is valid, and label it Timestamped.
7. Add/adjust regression tests for:
   - A valid B-B report shows a green/valid verdict and Basic preservation.
   - A valid B-T report shows a green/valid verdict and Timestamped preservation.
   - Inconclusive trust remains yellow even when preservation says Basic or
     Timestamped.
   - Invalid digest/modification remains red regardless of preservation label.
8. Run the CEISign test suite and an iOS simulator build. Do not move trust
   fetch/pin logic into SDTrustKit.

Deliverables:
- Minimal CEISignPDFValidation adapter changes.
- UI display of the preservation label near the existing signature badge/details.
- Tests covering the badge-color versus preservation-label distinction.
- A short summary of any remaining behavior differences from the previous
  Swift verifier.
```
