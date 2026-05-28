# PDF Generator vs EU DSS Gap Tracker

Date started: 2026-05-27

This document tracks the validator gaps found by benchmarking the malformed
`pdf-generator` corpus against EU DSS 6.2. The DSS run used a custom
`ValidatePdfgen` harness that trusts the generated per-case signing roots and
the generated TSA root, so the comparison focuses on malformations rather than
EU LOTL trust membership.

## Inputs

- Generated PDFs: `/Users/cristian/Development/pdf-generator/output`
- DSS reports: `/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-pdfgen-trust`
- Comparison JSON: `/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-comparison.json`
- DSS harness: `/Users/cristian/Development/signed_pdfs/dss-validator/src/main/java/ValidatePdfgen.java`

The comparison covered 81 PDFs across 10 generated runs.

## Stage 0 Guardrails

Stage 0 locks the current baseline before the next parity fixes.

Command:

```sh
./scripts/stage0_guardrails.sh
```

The guardrail currently enforces:

- `cargo test --manifest-path rust/sd_trust_kit/Cargo.toml`
- all pdf-generator manifest cases match their expected validator outcome
- `/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-comparison.json`
  still has 81 inputs, zero manifest mismatches, and exactly six accepted
  structural diagnostic differences against DSS:
  - `byterange-first-not-zero`: 1
  - `byterange-overlap`: 5

Status: passing on 2026-05-27.

## Stage 1: PAdES Baseline CMS Conformance

Stage 1 starts addressing EU DSS source-code gap D-003. The validator now flags
non-baseline CMS/PAdES structure before a cryptographically valid CMS can be
reported as acceptable.

Implemented checks:

- `SignedData.signerInfos` must contain exactly one signerInfo.
- PAdES CMS content must be detached; encapsulated `eContent` is rejected.
- `encapContentInfo.eContentType` must be `id-data`.
- signed attributes are required.
- signed `content-type` must be present exactly once and equal `id-data`.
- signed `message-digest` must be present exactly once.
- exactly one `signing-certificate` or `signing-certificate-v2` attribute must
  be present.
- the signing-certificate attribute must hash the resolved signer certificate.
- v1 `signing-certificate` is only accepted for SHA-1 signatures.

DSS parity note:

- SHA-1 signatures using `signing-certificate-v2` are accepted when the
  attribute hash matches. The pdf-generator control case is accepted by DSS and
  remains valid under the Stage 1 guardrails.

Regression coverage:

- added signed-pdfs-backed tests for multiple signerInfos, encapsulated CMS
  content, missing signed attributes, and missing `message-digest`.
- the Swift offline corpus comparison normalizes this new Rust policy step so
  older Swift snapshots still protect against unrelated regressions.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## Stage 2: PDF Signature Discovery Trust Boundary

Stage 2 starts addressing EU DSS source-code gap D-001. DSS/PDFBox does not
discover signature dictionaries from arbitrary bytes appended after the final
PDF EOF marker, while the Rust raw scanner previously could.

Implemented check:

- `/ByteRange` scanning now stops at the final `%%EOF` marker.
- unparseable-signature detection uses the same boundary.

Regression coverage:

- added a signed-pdfs-backed test that appends an orphan signature dictionary
  after the final EOF marker and verifies it is ignored.

Scope note:

- this is intentionally narrower than full AcroForm `/V` signature resolution.
  Final-field references alone are not enough, because legitimate older
  incremental signatures may no longer be referenced by the final field value.
  Full D-001 parity needs revision-aware field traversal.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## Stage 3: Signature Dictionary Revision Consistency

Stage 3 starts addressing EU DSS source-code gap D-002. DSS compares the
signature dictionary from the signed revision with the final document to catch
spoofing through later incremental updates.

Implemented check:

- when a signature dictionary is parsed from an indirect object, the validator
  compares that object's dictionary body in the signed revision against the
  latest object body for the same object number/generation in the final PDF.
- if the same signature object is redefined with changed dictionary content, the
  signature gets a `Document modified after signing` hard failure.

Regression coverage:

- added a signed-pdfs-backed test that appends a later revision redefining the
  same signature object with a changed `/Reason` while preserving the original
  CMS and ByteRange.
- the Swift offline corpus comparison normalizes this stricter Rust policy step
  for older Swift snapshots while preserving the rest of the signature evidence.

Scope note:

- this does not yet compare field/widget objects or detect final field `/V`
  swaps. Those need the revision-aware field traversal called out in D-001.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## Stage 4: Validation-Data Tail Object Rewrites

Stage 4 starts addressing EU DSS source-code gap D-004. DSS classifies later
incremental updates by comparing signed and final revisions; our validator
previously allowed a later `/DSS` validation-data tail even if that tail
redefined an object that already existed in the signed revision.

Implemented check:

- for non-DocTimeStamp signatures, a later revision containing `/DSS` is checked
  for existing-object rewrites.
- if the revision redefines a pre-existing object with changed content, the
  signature gets a `Document modified after signing` hard failure.
- legitimate LTV maintenance remains allowed when a catalog update only adds
  `/DSS`, adds `/DSS` plus a new document timestamp signature field, or extends
  an existing DSS/VRI-style validation dictionary.

Regression coverage:

- added a signed-pdfs-backed test that appends a fake `/DSS` revision while
  redefining an existing object.
- kept the CRL/LTV fixture valid; `0013.pdf` appends a document timestamp and is
  still accepted with the local revocation cache.

Scope note:

- this is not yet DSS's full object/annotation/visual comparison model. It closes
  one spoofing path for `/DSS`-looking tails while preserving known-good LTV
  revisions.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## Stage 5: Signature Field `/V` Revision Consistency

Stage 5 continues EU DSS source-code gaps D-001/D-002. DSS resolves signatures
through PDF signature fields, so a later incremental update that swaps a signed
field's `/V` reference away from the original signature dictionary is treated as
signature spoofing. Our raw `/ByteRange` scanner previously still validated the
original signature dictionary when its own object body was unchanged.

Implemented check:

- when the signed revision has a signature field/widget whose `/V` references the
  parsed signature dictionary, the final PDF is checked for a later redefinition
  of that same field object.
- if the later field object no longer points `/V` at the signed signature
  dictionary, the signature gets a `Document modified after signing` hard
  failure.

Regression coverage:

- added a signed-pdfs-backed test that appends a later revision redefining the
  field object from `/V <signed signature>` to another signature-looking object
  while preserving the original CMS and ByteRange.

Scope note:

- this is deliberately narrower than full AcroForm traversal. It catches field
  reference swaps for signatures that were field-referenced in their signed
  revision without rejecting raw-signature edge cases still present in the
  historical corpus.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## Stage 6: Revision-Aware AcroForm Traversal

Stage 6 deepens EU DSS source-code gap D-001. DSS resolves PDF signatures through
AcroForm signature fields and their `/V` references; the Rust validator now has a
revision-aware traversal foundation instead of relying only on raw `/ByteRange`
scanning for field-level checks.

Implemented check:

- resolve the latest catalog object in the signed revision.
- follow direct or indirect `/AcroForm /Fields`, then recursive `/Kids` field
  trees, including inherited `/FT /Sig`.
- count reachable signature fields whose `/V` references the parsed signature
  dictionary.
- report a `Signature field resolution` format failure when multiple reachable
  fields reference the same signature dictionary.
- Stage 5's later `/V` swap check now uses this traversal, so it only considers
  fields reachable from the signed revision's AcroForm field tree.

Regression coverage:

- added PDF-module tests for nested `/Kids` traversal, inherited `/FT /Sig`, and
  latest-object handling inside a revision.
- the Swift offline corpus comparison normalizes the new stricter Rust diagnostic;
  it currently flags `0130.pdf` as multiple fields referencing the same signature
  dictionary.

Scope note:

- this still does not reject every in-file orphan `/Sig` dictionary. The next
  D-001 slice should use the traversal to compare parsed raw signatures against
  the complete signed-revision field set, with careful exceptions for historical
  raw-signature edge cases.

Status: passing on 2026-05-27 via `./scripts/stage0_guardrails.sh`.

## High-Level Read

The Rust validator is strong on basic PDF/CMS integrity checks:

- document digest mismatch
- corrupted CMS signature value
- replaced CMS signature value
- tampered messageDigest attribute
- malformed or unreadable `/Contents`
- bad document timestamp imprint
- invalid document timestamp signature

The weak areas found in the first benchmark were:

- signature timestamp token validation and severity
- timestamp `eContentType` validation
- certificate validity and usage constraints
- some ByteRange sub-indication differences
- policy treatment of revocation and proof-of-existence cases

## Gap Inventory

### G-001: Signature Timestamp Wrong eContentType Accepted

Affected cases:

- `ts-wrong-econtenttype` in runs `20260523-185941`, `20260523-190042`,
  `20260523-190456`

DSS behavior:

- DSS finds no usable signature for these PDFs.

Rust behavior:

- The validator returns `valid/passed/none`.

Risk:

- High. A malformed RFC 3161 token can be accepted as if it were valid
  timestamp evidence.

Expected fix direction:

- Enforce RFC 3161 signed-data `eContentType == id-ct-TSTInfo`.
- If the timestamp token is present but has the wrong content type, surface a
  timestamp format failure.
- Decide whether a broken signature timestamp invalidates the whole signature or
  produces an indeterminate result under the project policy.

Fix:

- Added RFC 3161 `id-ct-TSTInfo` enforcement for signature timestamp tokens.
- Added a focused regression test for `ts-wrong-econtenttype`.

Status: fixed

### G-002: Invalid Signature Timestamp Downgraded to Warning

Affected cases:

- `ts-sig-invalid`
- `ts-token-corrupted`
- `ts-imprint-mismatch`
- `ts-gentime-after-tsa-expiry`
- `ts-gentime-before-signer-validity`

DSS behavior:

- DSS reports timestamp failure signals for the signature timestamp.

Rust behavior:

- The validator generally returns `warning` with timestamp-related
  sub-indications.

Risk:

- High. A document with broken timestamp evidence may look acceptable to
  callers that treat warnings as usable signatures.

Expected fix direction:

- Separate signature validity from timestamp evidence validity explicitly.
- If a claimed PAdES-B-T signature contains a malformed timestamp token, do not
  let the overall report be `valid` or weak `warning` unless that is an explicit
  caller policy.
- Map timestamp imprint mismatch and timestamp signature failure to stronger
  ETSI-style indications.

Fix:

- Signature timestamp CMS parse failures, missing `signerInfos`, imprint
  mismatches, timestamp signature failures, and invalid TSA trust constraints are
  now hard failures or indeterminate evidence failures instead of soft warnings.
- Added focused regression tests for invalid timestamp signatures, imprint
  mismatch, TSA certificate validity, and missing TSA timestamp EKU.

Status: fixed

### G-003: Document Timestamp Wrong eContentType Ambiguity

Affected cases:

- `doc-ts-wrong-econtenttype` in runs `20260523-185941`, `20260523-190042`,
  `20260523-190456`

DSS behavior:

- DSS does not flag this generated document timestamp as a core failure in the
  extracted comparison.

Initial Rust behavior:

- The validator returns `valid/passed/none`.

Risk:

- Medium. This may be a generator issue, a DSS interpretation nuance, or a real
  validator blind spot. It needs byte-level inspection before changing behavior.

Fix:

- Document timestamps now also enforce RFC 3161 `id-ct-TSTInfo`.
- The generated `doc-ts-wrong-econtenttype` cases now fail as expected by the
  generator manifest, even though DSS core does not expose this as the primary
  failure in the extracted summary.

Status: fixed

### G-004: Certificate Validity and Usage Constraints Not Decisive

Affected cases:

- `cert-expired`
- `cert-not-yet-valid`
- `cert-wrong-eku`
- `cert-no-signing-key-usage`

DSS behavior:

- DSS reports chain/revocation-policy issues with generated trust roots; this
  was not a clean oracle for these cases.

Rust behavior:

- The validator often reports `warning/timestampEvidenceIssue` rather than a
  decisive certificate validity or constraints problem.

Risk:

- High for production validation. Expired, not-yet-valid, or wrong-purpose
  signing certificates should not be hidden behind timestamp warnings.

Expected fix direction:

- Evaluate signer certificate validity at the claimed signing time and/or best
  signature time.
- Enforce key usage for document signing.
- Enforce EKU constraints where applicable for document-signing certificates.
- Preserve timestamp diagnostics without letting them mask certificate failures.

Fix:

- Added signer certificate validity checks for trusted B-B signatures that do
  not have a trusted proof-of-existence timestamp.
- Added signer certificate key usage and EKU checks once the signer chain is
  trusted.
- Kept these checks from masking ByteRange coverage warnings in legacy corpus
  comparisons.
- Added focused regression tests for expired signer certificates, wrong signer
  EKU, and missing signing key usage.

Status: fixed

### G-005: ByteRange Sub-Indication Differences

Affected cases:

- `byterange-overlap`
- `byterange-first-not-zero`

DSS behavior:

- DSS often reports hash failure because the reference data object is not intact.

Rust behavior:

- The validator rejects these as `formatIssue`.

Risk:

- Low-to-medium. Behaviorally, both validators reject. This is mostly parity and
  diagnostic mapping unless downstream callers depend on exact sub-indications.

Expected fix direction:

- Keep rejection behavior.
- Decide whether the project wants DSS-like sub-indications or stricter
  structural format labels for impossible ByteRange definitions.

Resolution:

- Left as an intentional diagnostic difference for now. Rust rejects these
  signatures as malformed PDF signature structure (`formatIssue`); DSS core
  reports a hash/data-object failure for the same rejected inputs.
- Current comparison has 6 behaviorally rejected cases in this bucket:
  5 `byterange-overlap`, 1 `byterange-first-not-zero`.

Status: accepted difference

### G-006: Revocation and Proof-of-Existence Policy Differences

Affected cases:

- `signer-revoked`
- `crl-expired`
- `crl-bad-signature`
- `crl-unreachable`

DSS behavior:

- With generated roots and local CRLs, DSS still applies broader policy checks
  around revocation evidence and trusted-list qualification.

Rust behavior:

- Revoked signer is reported invalid.
- CRL unavailable, expired, and bad-signature cases are warnings.

Risk:

- Medium. Some of this is policy, but callers need predictable behavior for
  revocation evidence failures.

Expected fix direction:

- Define project policy for no proof-of-existence, revoked certificate, and
  unavailable revocation evidence.
- Ensure report aggregation does not hide revocation results behind timestamp
  warnings.

Fix:

- Updated report aggregation so revoked certificates, unavailable revocation
  evidence, and no-POE validity failures produce indeterminate evidence results
  instead of being flattened into unrelated timestamp warnings.
- The current manifest benchmark matches the generator expectations for
  `signer-revoked`, `crl-expired`, `crl-bad-signature`, and `crl-unreachable`.

Status: fixed

## Final Verification

Completed on 2026-05-27:

- Combined corpus folder created at
  `/Users/cristian/Development/SDTrustKit/validation-corpus/combined-pdfs`
  with 1534 PDFs copied from `signed_pdfs` and `pdf-generator`.
- EU DSS harness rerun against `/Users/cristian/Development/pdf-generator/output`
  with generated signing roots and TSA root trusted: 81 PDFs, 81 DSS reports,
  0 harness errors.
- Rust generator manifest comparison regenerated at
  `/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-comparison.json`:
  81 inputs, 0 manifest mismatches.
- Remaining DSS/Rust comparison differences are the accepted ByteRange
  sub-indication differences listed in G-005.
- Rust tests:
  - `cargo test --test pdf_generator_malformed`: 9 passed.
  - `cargo test`: passed, with the pre-existing ignored full-network corpus
    parity test still ignored.

## Verification Checklist

For each fix:

1. Add or update focused Rust tests using the generated corpus.
2. Run `cargo test` from `rust/sd_trust_kit`.
3. Rebuild the DSS harness if needed.
4. Rerun DSS against the combined corpus.
5. Regenerate the comparison summary.
6. Update this document with fixed and remaining gaps.
