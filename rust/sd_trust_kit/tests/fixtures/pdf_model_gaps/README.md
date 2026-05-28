# PDF Model Gap Fixtures

Generated on 2026-05-27 from:

- `/Users/cristian/Development/pdf-generator/output/20260523-190456/control-valid.pdf`
- `scripts/generate_pdf_model_gap_fixtures.py`

These fixtures target remaining PDF/PAdES model gaps before implementing more
validator changes. They are intentionally limited to cases EU-DSS 6.2 confirmed
as malformed under the pdf-generator trust-anchor harness.

EU-DSS command:

```sh
java -cp /Users/cristian/Development/signed_pdfs/dss-validator/target/dss-corpus-validator-jar-with-dependencies.jar \
  ValidatePdfgen \
  rust/sd_trust_kit/tests/fixtures/pdf_model_gaps \
  rust/sd_trust_kit/tests/fixtures/pdf_model_gaps_dss_reports
```

Confirmed malformed cases:

- `byterange-decimal-entry.pdf`: `TOTAL_FAILED / FORMAT_FAILURE`
- `byterange-negative-entry.pdf`: `TOTAL_FAILED / FORMAT_FAILURE`
- `duplicate-field-reference-later-revision.pdf`: `TOTAL_FAILED / FORMAT_FAILURE`
- `field-name-changed-after-signing.pdf`: `TOTAL_FAILED / FORMAT_FAILURE`

Control:

- `control-valid.pdf`: not a malformed oracle. In this offline harness it is
  indeterminate because revocation/trust evidence is not fully available, but it
  is not reported as `TOTAL_FAILED`.

Rejected during fixture triage:

- widget rectangle changes, page content stream redefinition, post-EOF orphan
  signature objects, field `/V` swaps, and one huge `/ByteRange` token variant
  were generated experimentally but not kept here because this DSS run did not
  produce a clean `TOTAL_FAILED / FORMAT_FAILURE` PDF-model oracle for them.
