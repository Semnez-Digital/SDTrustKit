#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const comparisonPath =
  process.argv[2] ||
  process.env.DSS_COMPARISON_JSON ||
  '/Users/cristian/Development/signed_pdfs/reports/pdf-generator-dss-comparison.json';

const expectedInputs = Number(process.env.STAGE0_EXPECTED_INPUTS || 81);
const acceptedGaps = new Map([
  ['byterange-first-not-zero', 1],
  ['byterange-overlap', 5],
]);

function fail(message) {
  console.error(`Stage 0 DSS guardrail failed: ${message}`);
  process.exit(1);
}

if (!fs.existsSync(comparisonPath)) {
  fail(`comparison JSON not found at ${comparisonPath}`);
}

const comparison = JSON.parse(fs.readFileSync(comparisonPath, 'utf8'));
if (comparison.inputs !== expectedInputs) {
  fail(`expected ${expectedInputs} inputs, got ${comparison.inputs}`);
}
if (comparison.manifestMismatchCount !== 0) {
  fail(`expected no manifest mismatches, got ${comparison.manifestMismatchCount}`);
}

const gaps = Array.isArray(comparison.gaps) ? comparison.gaps : [];
const actualGapCount = gaps.reduce((sum, gap) => sum + Number(gap.n || 0), 0);
const expectedGapCount = [...acceptedGaps.values()].reduce((sum, n) => sum + n, 0);
if (comparison.gapCount !== expectedGapCount || actualGapCount !== expectedGapCount) {
  fail(
    `expected ${expectedGapCount} accepted structural DSS/Rust diagnostic gaps, ` +
      `got gapCount=${comparison.gapCount}, summed=${actualGapCount}`,
  );
}

for (const gap of gaps) {
  const expected = acceptedGaps.get(gap.case);
  if (expected === undefined) {
    fail(`unexpected DSS/Rust gap for ${gap.case}`);
  }
  if (gap.n !== expected) {
    fail(`gap ${gap.case} expected count ${expected}, got ${gap.n}`);
  }
}
for (const [caseId, expected] of acceptedGaps) {
  const actual = gaps.find((gap) => gap.case === caseId)?.n || 0;
  if (actual !== expected) {
    fail(`accepted gap ${caseId} expected count ${expected}, got ${actual}`);
  }
}

const rel = path.relative(process.cwd(), comparisonPath);
console.log(
  `Stage 0 DSS guardrail OK: ${comparison.inputs} inputs, ` +
    `0 manifest mismatches, ${expectedGapCount} accepted structural diagnostic gaps (${rel})`,
);
