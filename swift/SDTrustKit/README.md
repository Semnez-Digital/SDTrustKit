# SDTrustKit Swift Wrapper Prototype

Thin Swift package that calls the shared Rust PDF validation core through the C
ABI. This package does not validate PDFs itself; it owns platform-side loading,
options JSON encoding, FFI memory handling, and report decoding.

Build the Rust dynamic library first:

```sh
cargo build --release --manifest-path ../../rust/sd_trust_kit/Cargo.toml
```

Then run the Swift smoke tests:

```sh
swift test
```

By default the wrapper loads:

```text
../../rust/sd_trust_kit/target/release/libsd_trust_kit.dylib
```

Set `SD_TRUST_KIT_DYLIB` to point at a different local build.

Current scope:

- calls `sd_trust_kit_verify_pdf_json`
- calls `sd_trust_kit_verify_pdf_with_options_json`
- calls `sd_trust_kit_verify_pdf_including_revocation_with_options_json`
- encodes caller-owned trust anchors, timestamp pins, and CRL cache entries
- decodes the Rust `ValidationReport` JSON into Swift DTOs
- compares one corpus PDF against the Rust CLI output when the sibling reference
  corpus is present
