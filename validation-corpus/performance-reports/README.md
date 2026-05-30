# Performance Reports

This directory contains public-facing benchmark artifacts for SDTrustKit.

The current report is:

- `2026-05-28-public-offline-pdf-validation/report.html`
- `2026-05-28-public-offline-pdf-validation/README.md`
- `2026-05-28-public-offline-pdf-validation/summary.json`

`latest-pdf-benchmark.html` is a copy of the current HTML report for convenient
linking.

## Scope

The current benchmark compares offline PDF validation timing across SDTrustKit,
EU DSS, and pyHanko on the symlink-expanded `validation-corpus/combined-pdfs`
corpus. The report is intended to document local validation latency and broad
result categories. It is not a conformance certification.

Network fetching is disabled or avoided in the benchmark configuration. This is
intentional: SDTrustKit is designed to receive trust, timestamp, EU trusted-list,
and revocation material from the embedding application instead of fetching it
itself.

## Reading The Artifacts

- `sdtrustkit.tsv`: raw SDTrustKit timing rows.
- `eu-dss.tsv`: raw EU DSS timing and `SimpleReport` rows.
- `pyhanko.tsv`: raw pyHanko timing rows.
- `comparison.tsv`: joined per-file comparison.
- `summary.json`: machine-readable aggregate statistics.
- `report.html`: human-readable report suitable for publication.

The raw rows are kept alongside the report so future benchmark updates can be
reviewed rather than accepted on trust.
