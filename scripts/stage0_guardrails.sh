#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rust_manifest="$repo_root/rust/sd_trust_kit/Cargo.toml"
comparison_json="${DSS_COMPARISON_JSON:-/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-comparison.json}"

echo "==> Rust validator tests"
cargo test --manifest-path "$rust_manifest"

echo "==> EU DSS pdf-generator comparison snapshot"
node "$repo_root/scripts/check_pdf_generator_dss_baseline.mjs" "$comparison_json"

echo "==> Stage 0 guardrails passed"
