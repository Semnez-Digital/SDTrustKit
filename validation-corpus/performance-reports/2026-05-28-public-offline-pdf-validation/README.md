# Offline PDF Validation Benchmark: SDTrustKit, EU DSS, and pyHanko

Generated: 2026-05-28T17:13:27+00:00

This report compares offline PDF signature validation timing across three validators:

- SDTrustKit 1.0.0
- EU DSS 6.2, through the checked-in offline benchmark harness
- pyHanko 0.35.1

The corpus contains 1,665 symlink-expanded PDFs under `validation-corpus/combined-pdfs`, including public signed PDFs, EU DSS fixture material, generated malformed cases, unsigned inputs, and stress files.

## What This Report Is

This is a reproducible engineering benchmark for local, offline validation behavior. It is useful for understanding throughput, latency distribution, parser stress cases, and broad result categories on a heterogeneous corpus.

## What This Report Is Not

This is not a conformance certification. The validators do not implement identical trust policy, revocation policy, PDF-diff policy, or long-term validation semantics. Many `Inconclusive` results are expected because the run disables network fetching and does not load a full public trust store.

## Methodology

Each validator was run with one warmup iteration and three measured iterations per PDF. The reported timing for a row is the arithmetic mean of the three measured runs.

Network access was disabled or avoided by policy:

- SDTrustKit reads local PDF bytes and uses only caller-supplied offline inputs.
- EU DSS uses `IgnoreDataLoader` for AIA, CRL, and OCSP and a macOS sandbox profile with `(deny network*)`.
- pyHanko uses `ValidationContext(..., allow_fetching=False, revocation_mode="soft-fail")`.

The synthetic pdf-generator roots used by the generated fixture set are supplied to EU DSS and pyHanko so generated control cases are not penalized merely because their local root is absent.

## Timing Summary

| Validator | Average | Median | p95 | p99 | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| SDTrustKit | 62.069 ms | 7.115 ms | 158.575 ms | 1181.831 ms | 15524.742 ms |
| EU DSS | 178.154 ms | 88.903 ms | 406.587 ms | 1183.369 ms | 23744.62 ms |
| pyHanko | 78.454 ms | 48.721 ms | 180.717 ms | 733.576 ms | 5413.815 ms |

## Relative Timing

| Ratio | Median | p95 | p99 | Max |
| --- | ---: | ---: | ---: | ---: |
| EU DSS / SDTrustKit | 13.934x | 63.532x | 121.465x | 456.367x |
| pyHanko / SDTrustKit | 4.867x | 16.0x | 27.864x | 37.3x |
| pyHanko / EU DSS | 0.446x | 2.656x | 3.929x | 8.873x |

## Result Categories

These categories are coarse aggregates for comparison only. See the raw files for detailed DSS indications, SDTrustKit standards fields, and pyHanko summaries.

| Validator | Distribution |
| --- | --- |
| SDTrustKit | `{"Error": 7, "Inconclusive": 1526, "Invalid": 96, "NO_SIGNATURES": 36}` |
| EU DSS | `{"Error": 10, "Inconclusive": 1520, "Invalid": 94, "NO_SIGNATURES": 41}` |
| pyHanko | `{"Error": 377, "Inconclusive": 1229, "Invalid": 35, "NO_SIGNATURES": 23, "Valid": 1}` |

pyHanko reports errors for a number of hybrid-reference and strict diff-policy cases in this offline configuration. They are counted separately instead of being coerced into invalid signatures.

## Files

- `sdtrustkit.tsv`: raw SDTrustKit timing and report summary rows.
- `eu-dss.tsv`: corrected EU DSS offline timing and `SimpleReport` verdict rows.
- `pyhanko.tsv`: raw pyHanko timing and status summary rows.
- `comparison.tsv`: joined per-file comparison across all three validators.
- `summary.json`: machine-readable aggregate statistics.
- `report.html`: public-facing HTML report.
- `BenchmarkSDTrustKit.rs`, `BenchmarkEUDSS.java`, `BenchmarkPyHanko.py`: benchmark harnesses.
- `no-network.sb`: macOS sandbox profile used for the EU DSS run.

## Reading The Numbers

SDTrustKit is optimized for embedding in client applications where local validation latency matters. EU DSS and pyHanko are mature general-purpose validation stacks with broader policy surfaces and different defaults. The benchmark is therefore best read as a latency and integration-cost study, not as a claim that one validator is a drop-in replacement for another.
