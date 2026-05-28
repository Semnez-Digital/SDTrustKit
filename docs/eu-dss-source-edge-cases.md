# EU DSS Source Edge-Case Notes

Date: 2026-05-27

This note records edge cases found by reading the EU DSS 6.2 source after the
`pdf-generator` parity pass. It is intentionally focused on places where our
validator may still diverge even after the generated malformed corpus reaches
the expected DSS-facing outcome.

## Source Baseline

EU DSS sources were fetched from Maven source jars and unpacked under:

- `/tmp/dss-6.2-src`

Primary files inspected:

- `dss-pades-pdfbox-6.2/.../PdfBoxDocumentReader.java`
- `dss-pades-6.2/.../pdf/AbstractPDFSignatureService.java`
- `dss-pades-6.2/.../pades/validation/ByteRange.java`
- `dss-pades-6.2/.../pades/validation/PAdESBaselineRequirementsChecker.java`
- `dss-pades-6.2/.../pades/validation/CMSForPAdESBaselineRequirementsChecker.java`
- `dss-cades-6.2/.../cades/validation/CAdESBaselineRequirementsChecker.java`
- `dss-spi-6.2/.../spi/validation/TimestampTokenVerifier.java`
- `dss-spi-6.2/.../spi/x509/tsp/TimestampToken.java`
- `dss-pades-6.2/.../pdf/modifications/DefaultPdfDifferencesFinder.java`
- `dss-pades-6.2/.../pdf/modifications/DefaultPdfObjectModificationsFinder.java`
- `dss-pades-6.2/.../pdf/modifications/PdfObjectModificationsFilter.java`
- `dss-validation-6.2/.../vpfltvd/ValidationProcessForSignaturesWithLongTermValidationData.java`
- `dss-validation-6.2/.../bbb/xcv/sub/SubX509CertificateValidation.java`
- `dss-policy-jaxb-6.2/policy/constraint.xml`

## Highest-Risk Remaining Gaps

### D-001: Signature Dictionary Discovery Uses Different Trust Boundary

DSS extracts signature dictionaries from PDF signature fields and their `/V`
references through PDFBox. It also warns when more than one field points to the
same signature dictionary. Our parser scans raw bytes for `/ByteRange` and then
accepts objects that look like signature dictionaries.

Stage 2 narrowed the raw-scan trust boundary by stopping signature discovery at
the final `%%EOF` marker. This matches the practical PDF parser boundary for
bytes appended after the final file body and prevents a trailing orphan
signature dictionary from being validated. It does not yet implement full
AcroForm field-tree traversal or per-revision `/V` resolution; a first attempt
using only final `/V` references dropped legitimate earlier revision signatures
in the Swift corpus, so that broader fix needs a revision-aware model.

Risk:

- We may validate an orphaned or unreachable `/Sig` dictionary that DSS ignores.
- We may miss field-level issues, duplicate field references, or spoofing cases
  where the visible field and raw dictionary do not line up.

Recommended tests:

- Orphan `/Sig` object with valid CMS but no AcroForm field reference.
- Two fields sharing the same `/V` signature dictionary.
- Field `/V` points to one dictionary while another raw dictionary appears
  earlier/later in the file.

Status: partially fixed in Stage 2 for trailing post-EOF orphan dictionaries,
Stage 5 for signed-revision field `/V` swaps, and Stage 6 for revision-aware
AcroForm traversal plus duplicate field-reference diagnostics. Remaining D-001
work is stricter revision-aware signature discovery and orphan in-file
signature handling.

### D-002: Signature Dictionary Consistency Across Revisions

DSS reloads the signed revision and compares the signature dictionary in that
revision against the final document's dictionary. This is specifically called
out as spoofing detection. Our current checks verify ByteRange coverage and
later-revision shape, but they do not reconstruct the signed revision and compare
the field-resolved signature dictionary.

Stage 3 added a same-object revision check: when a parsed signature dictionary
comes from an indirect object, the validator compares that object's dictionary
in the signed revision against the latest revision of the same object in the
final PDF. If the later object body differs, the signature is reported as
document-modified-after-signing. This catches direct spoofing where a later
incremental update rewrites `/Name`, `/Reason`, `/M`, `/SubFilter`, or similar
dictionary fields while preserving the original CMS and ByteRange.

Risk:

- A malicious later revision may alter visible or field-level signature metadata
  while preserving enough structure for our heuristic to pass or warn.

Recommended tests:

- Later revision changes `/Name`, `/Reason`, `/M`, `/SubFilter`, field name, or
  widget properties for an existing signature.
- Later revision swaps a field reference while leaving the signed CMS untouched.

Status: partially fixed in Stage 3 for same-object signature dictionary
redefinitions and Stage 5 for field `/V` swaps away from a signed signature
dictionary. Remaining work is broader field/widget property comparison, which
requires the revision-aware field model from D-001.

### D-003: PAdES Baseline CMS Attribute Conformance Is Much Stricter

DSS checks PAdES Baseline-B conformance before considering profile level. For a
PDF signature it requires exactly one `signerInfo`, detached CMS content, CMS
certificates, signed `content-type`, signed `message-digest`, exactly one
`signing-certificate` or `signing-certificate-v2`, and the signing certificate
present in `SignedData.certificates`. It also requires PAdES signed
`content-type == id-data`, requires `ETSI.CAdES.detached` for baseline PAdES
signatures, and has profile-specific handling for the optional `signing-time`
attribute.

Stage 1 added default checks for the high-signal CMS structure and signed
attribute rules: multiple signerInfos, encapsulated eContent, non-id-data
encapsulated content type, missing signed attributes, missing/duplicate
`content-type`, missing/duplicate `message-digest`, missing/duplicate
`signing-certificate` or `signing-certificate-v2`, and signing-certificate hash
mismatches. It also enforces that v1 `signing-certificate` is only used with
SHA-1 signatures. It intentionally does not reject SHA-1 signatures that use
`signing-certificate-v2`, because the pdf-generator control corpus and DSS
parity accept that combination when the attribute hash is correct.

Risk:

- Structurally non-conformant but cryptographically valid CMS may be reported as
  valid.
- Multi-signer or encapsulated-content CMS can be mishandled because we validate
  only the first signer.

Recommended tests:

- Two signerInfos, first valid and second malformed.
- Encapsulated eContent present in a PAdES signature.
- Missing or non-id-data signed `content-type`.
- Missing, duplicate, mismatched, or wrong-hash `signing-certificate`
  attributes.
- `/SubFilter /adbe.pkcs7.detached` vs `/ETSI.CAdES.detached` when claiming
  baseline PAdES.
- PAdES CMS with signed `signing-time` present.

Status: partially fixed in Stage 1. Remaining work is primarily `/SubFilter`
profile semantics, certificate-presence cardinality beyond signer resolution,
and deciding whether `signing-time` belongs in a separate strict profile mode.

### D-004: Incremental Update Classification Is Broader In DSS

DSS compares signed and final revisions at multiple levels: annotation overlap,
page count differences, visual page screenshots, and recursive catalog/object
differences. It classifies changes into secure extension, signature/form-fill,
annotation creation, or undefined changes.

Our current code allows trailing whitespace and a constrained DSS-validation-data
tail, rejects obvious risky markers, and now rejects `/DSS`-looking later
revisions that redefine pre-existing non-validation objects. Known-good LTV
maintenance remains allowed when a catalog update only adds `/DSS`, or adds
`/DSS` plus a new document timestamp signature field, or extends an existing
DSS/VRI-style validation dictionary. This is still not equivalent to DSS's
object and visual comparison model.

Risk:

- Allowed changes such as later signatures, empty-field fills, DocTimeStamp, PDF
  extensions, metadata, and some form fills may be over-rejected.
- Some object changes not covered by the marker list or the Stage 4 object
  rewrite check may be under-detected, especially if they do not include the
  obvious risky names.

Recommended tests:

- Add a second normal signature after the first signature.
- Fill an existing empty signature field.
- Add a DocTimeStamp revision.
- Add metadata/extensions only.
- Add or alter page content using object names not currently in our marker list.
- Annotation overlap and visual-difference cases.

Status: partially fixed in Stage 4 for `/DSS` tails that rewrite existing
objects. Remaining parity work is the broader DSS secure-extension, annotation,
field-fill, and visual-difference classification.

### D-005: Timestamp Validation Has More POE Semantics

DSS requires a timestamp token to be trusted, cryptographically valid, and backed
by acceptable certificate-chain/revocation validation when configured. It also
uses timestamp proof-of-existence to move the best-signature-time backward, then
checks timestamp order/coherence, timestamp delay policy, signer certificate
issuance/expiration at best-signature-time, and revocation time against that
best-signature-time.

Our validator now verifies signature/document timestamp imprint, RFC 3161
content type, TSA trust, TSA validity, and TSA EKU for the generated cases. It
does not yet implement the full DSS long-term proof-of-existence process.

Risk:

- Long-term signatures can diverge from DSS around expired/revoked signer
  certificates when a valid timestamp should or should not rescue the signature.
- Multiple timestamps can be accepted without DSS-style coherence and ordering.

Recommended tests:

- Signer certificate expired at validation time but valid at trusted timestamp
  production time.
- Signer certificate not yet valid at trusted timestamp production time.
- Revocation after trusted timestamp vs before trusted timestamp.
- Multiple signature timestamps out of chronological order.
- Document timestamp covering LT/LTA data vs not covering LT/LTA data.

### D-006: Revocation And Policy Coverage Is Still Simplified

DSS's policy and validation process cover OCSP, CRL, revocation data
availability, acceptable revocation selector result, revocation freshness,
revocation issuer validity/trust, certificate-hold, revoked/no-POE branches,
try-later, algorithm sunset dates, and context-specific key usage/EKU.

Our revocation logic is CRL-oriented and substantially simpler.

Risk:

- OCSP-only signatures and PAdES DSS/VRI embedded revocation data will diverge.
- Some revoked/on-hold/no-revocation-data outcomes will be mapped less precisely
  than DSS.
- Context-specific KU/EKU constraints may differ for signer, CA, TSA, and
  revocation issuer certificates.

Recommended tests:

- OCSP-only signer revocation.
- Embedded DSS/VRI OCSP/CRL material with no network access.
- Revoked before signing, revoked after signing with trusted timestamp, and
  certificate-hold cases.
- Revocation issuer expired/untrusted.
- Weak/expired digest and signature algorithm policy cases.

### D-007: ByteRange Parity Has Small Fuzz Edges

DSS's `ByteRange.validate()` requires four integers, first start `0`, nonnegative
lengths, and the second start not before the first covered part. It then compares
the extracted `/Contents` bytes against the ByteRange gap and checks extracted
signed-content length. Our logic is stricter about gap equality and bounds, which
is good, but the parser uses `usize` raw digit accumulation.

Risk:

- Very large integer tokens may overflow in debug builds or wrap in release
  semantics depending on compiler settings.
- Negative numbers and non-integer forms are rejected by our parser before they
  become diagnostic ByteRange failures.

Recommended tests:

- Huge ByteRange numbers larger than `usize`.
- Negative ByteRange entries.
- Decimal or indirect ByteRange entries.
- ByteRange with correct structural ordering but second range extending past EOF.

## Suggested Next Work

1. Extend malformed CMS/profile cases for the remaining D-003 subfilter,
   certificate-cardinality, and strict-profile questions.
2. Add raw-PDF field/reference edge cases for D-001 and D-002.
3. Decide whether we want strict PAdES Baseline conformance by default or a
   separate profile-conformance result beside cryptographic validity.
4. Expand incremental-update tests using DSS's secure/form-fill/annotation/
   undefined categories as the oracle.
5. Treat OCSP/DSS/VRI and long-term POE as a separate parity project; it is much
   larger than the malformed-signature corpus.
