# EU-DSS Fixture Ingestion

This repo keeps upstream EU-DSS fixtures out of git by default. The ingestion
script builds a local, pinned, reproducible mirror under `validation-corpus/`
and records normalized EU-DSS verdicts that we can use as benchmark input.

## Command

```sh
scripts/ingest_eu_dss_fixtures.py normalize
```

Defaults:

- DSS repo: `https://github.com/esig/dss.git`
- DSS commit: `d9473b8efea72fd5754623fa92bb9311f2b005c5`
- DSS Maven version: `6.2`
- Output root:
  `validation-corpus/eu-dss-fixtures/d9473b8efea72fd5754623fa92bb9311f2b005c5/`

The script performs a sparse checkout of only upstream `src/test/resources` and
`src/test/java`, mirrors resource files locally, indexes Java test references,
selects candidate signature containers, and runs EU-DSS offline over the
selection.

## Generated Files

- `index.json`: all mirrored upstream test resources with size, extension,
  hash, module, kind, and direct Java test references where detected.
- `test-resource-references.json`: resource path to Java test source paths.
- `java-test-index.json`: Java test source paths, detected class names, and
  normalized resource references.
- `selected-fixtures.json`: curated validation candidates selected from the
  resource index.
- `selected-fixtures.tsv`: compact input file for the Java normalizer.
- `reports/dss-normalized.jsonl`: raw one-row-per-fixture EU-DSS output.
- `normalized-manifest.json`: normalized expected-result manifest with source
  metadata, summary, and all per-fixture rows.
- `normalized-summary.json`: small aggregate summary for quick inspection.

## Offline Semantics

The normalizer uses EU-DSS with:

- `IgnoreDataLoader` for AIA, CRL, and OCSP loading.
- A sandbox profile that denies network access on macOS when `sandbox-exec` is
  available.
- An empty trusted certificate source.

That means this baseline is intentionally about parser/container/signature
behavior without network retrieval. Many cryptographically intact signatures
will be `Inconclusive` rather than `Valid` because there is no trust anchor.

## Current Full Run

The current full run normalized 762 selected fixtures:

- PAdES: 265
- CAdES: 116
- XAdES: 226
- ASiC: 155

EU-DSS aggregate verdicts in the offline baseline:

- `Inconclusive`: 545
- `NO_SIGNATURES`: 143
- `Invalid`: 58
- `Error`: 16

The selected fixture mirror is about 277 MB. The full ignored working area,
including sparse checkout and Maven normalizer build output, is about 738 MB.

## Useful Variants

Index only:

```sh
scripts/ingest_eu_dss_fixtures.py index
```

Smoke run:

```sh
scripts/ingest_eu_dss_fixtures.py normalize --limit 40 --work-root /tmp/eu-dss-fixture-smoke
```

Format-specific run:

```sh
scripts/ingest_eu_dss_fixtures.py normalize --formats pades
```

Size-capped run:

```sh
scripts/ingest_eu_dss_fixtures.py normalize --max-bytes 2000000
```

Filtered runs rewrite the selected fixture files under the chosen output root,
so use a temporary `--work-root` for experiments when preserving the full
baseline matters.

Use a different pinned DSS commit:

```sh
scripts/ingest_eu_dss_fixtures.py normalize --ref <commit-sha>
```

## Comparing SDTrustKit

After the DSS manifest exists, compare it with the local Rust validator:

```sh
cargo build --release --bin sd-trust-validate \
  --manifest-path rust/sd_trust_kit/Cargo.toml
scripts/compare_eu_dss_fixtures.py
```

Generated comparison files:

- `reports/sdtrustkit-vs-eu-dss.jsonl`: raw row-level comparison, including
  the SDTrustKit JSON report for PAdES inputs.
- `reports/sdtrustkit-vs-eu-dss.csv`: spreadsheet-friendly row-level
  comparison.
- `reports/sdtrustkit-vs-eu-dss-summary.json`: aggregate counts.

The current validator is PAdES/PDF-only. The comparison therefore records
CAdES, XAdES, and ASiC fixtures as `unsupported` on the SDTrustKit side rather
than running them through a PDF parser and producing misleading results.
