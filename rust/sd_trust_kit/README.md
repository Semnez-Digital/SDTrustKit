# SDTrustKit Rust Core

Portable Rust validation core for PAdES/PDF signature verification. The Swift
package in `Packages/CEISignPDFValidation` remains the reference implementation
until the Rust snapshots match the checked-in baselines.

Phase 1 is intentionally offline and deterministic:

- parse PDF signature dictionaries and `/ByteRange`
- parse CMS `SignedData`
- validate `messageDigest`
- verify CMS signatures for RSA PKCS#1 v1.5, RSA-PSS, and ECDSA algorithms
- extract signer/certificate metadata
- validate RFC 3161 timestamp message imprints and TSA signatures
- evaluate pinned offline anchors where enough chain data is available
- load caller-owned trust fixtures for deterministic parity/debug runs

Network-backed revocation refresh, EU trusted-list refresh, and higher-level
Swift/Kotlin/C# wrappers are deliberately deferred. Wrappers are dessert, not
dinner.

Run from this directory once Rust is installed:

```sh
cargo test
```

For one-off local inspection, the crate also builds a small JSON-report CLI:

```sh
cargo run --bin sd-trust-validate -- --pretty /path/to/file.pdf
cargo run --bin sd-trust-validate -- --offline-fixtures tests/fixtures /path/to/file.pdf
cargo run --bin sd-trust-validate -- --full-fixtures tests/fixtures /path/to/file.pdf
```

The first C ABI is available for wrapper prototypes:

```c
#include "include/sd_trust_kit.h"

char *json = sd_trust_kit_verify_pdf_json(pdf_bytes, pdf_len);
sd_trust_kit_free_string(json);
```

Use `sd_trust_kit_verify_pdf_including_revocation_with_options_json` when a wrapper
has deterministic CRL cache entries to pass into the core.

Build the native library with:

```sh
cargo build --release
```

A thin Swift wrapper prototype is available at
`../../swift/SDTrustKit`.
