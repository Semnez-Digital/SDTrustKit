#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE_RUN = Path("/Users/cristian/Development/pdf-generator/output/20260523-190456")
CONTROL_PDF = SOURCE_RUN / "control-valid.pdf"
CONTROL_PKI = SOURCE_RUN / "control-valid"
TSA_ROOT = SOURCE_RUN / "tsa-root.cert.pem"
OUT = REPO / "rust/sd_trust_kit/tests/fixtures/pdf_model_gaps"


def object_body(pdf: bytes, number: int, generation: int = 0, last: bool = True) -> bytes:
    pattern = re.compile(
        rb"(?m)(%d)\s+(%d)\s+obj(?P<body>.*?)endobj" % (number, generation),
        re.DOTALL,
    )
    matches = list(pattern.finditer(pdf))
    if not matches:
        raise ValueError(f"object {number} {generation} not found")
    return matches[-1 if last else 0].group("body").strip()


def last_startxref(pdf: bytes) -> int:
    matches = list(re.finditer(rb"startxref\s+(\d+)\s+%%EOF", pdf))
    if not matches:
        raise ValueError("startxref not found")
    return int(matches[-1].group(1))


def append_incremental(pdf: bytes, objects: list[tuple[int, int, bytes]], root=(7, 0)) -> bytes:
    out = bytearray(pdf)
    if not out.endswith(b"\n"):
        out.extend(b"\n")
    offsets: list[tuple[int, int, int]] = []
    for number, generation, body in objects:
        offsets.append((number, generation, len(out)))
        out.extend(f"{number} {generation} obj\n".encode())
        out.extend(body)
        if not body.endswith(b"\n"):
            out.extend(b"\n")
        out.extend(b"endobj\n")

    xref_offset = len(out)
    out.extend(b"xref\n")
    for number, generation, offset in offsets:
        out.extend(f"{number} 1\n".encode())
        out.extend(f"{offset:010d} {generation:05d} n \n".encode())
    size = max(max(number for number, _, _ in offsets) + 1, 1001)
    out.extend(b"trailer\n")
    out.extend(
        f"<< /Size {size} /Root {root[0]} {root[1]} R /Prev {last_startxref(pdf)} >>\n".encode()
    )
    out.extend(f"startxref\n{xref_offset}\n%%EOF\n".encode())
    return bytes(out)


def replace_first_byterange(pdf: bytes, replacement: bytes) -> bytes:
    match = re.search(rb"/ByteRange\s*\[(?P<values>[^\]]+)\]", pdf)
    if not match:
        raise ValueError("/ByteRange not found")
    start, end = match.span("values")
    original_len = end - start
    if len(replacement) > original_len:
        raise ValueError("replacement is longer than original ByteRange values")
    return pdf[:start] + replacement.ljust(original_len, b" ") + pdf[end:]


def cases(control: bytes) -> dict[str, bytes]:
    field = object_body(control, 14)
    acroform = object_body(control, 13)
    duplicate_field = (
        b"<< /FT /Sig /T (DuplicateSignatureField) /Type /Annot /Subtype /Widget "
        b"/F 132 /Rect [ 10 10 120 60 ] /P 5 0 R /V 15 0 R >>"
    )
    return {
        "field-name-changed-after-signing.pdf": append_incremental(
            control, [(14, 0, field.replace(b"/T (Signature1)", b"/T (SpoofedName)"))]
        ),
        "duplicate-field-reference-later-revision.pdf": append_incremental(
            control,
            [
                (998, 0, duplicate_field),
                (13, 0, acroform.replace(b"/Fields [ 14 0 R 17 0 R ]", b"/Fields [ 14 0 R 17 0 R 998 0 R ]")),
            ],
        ),
        "byterange-negative-entry.pdf": replace_first_byterange(control, b"-1 418 19470 512"),
        "byterange-decimal-entry.pdf": replace_first_byterange(control, b"0.0 4 19470 512"),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for path in OUT.glob("*"):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)

    control = CONTROL_PDF.read_bytes()
    shutil.copy(CONTROL_PDF, OUT / "control-valid.pdf")
    shutil.copy(CONTROL_PKI / "root.cert.pem", OUT / "root.cert.pem")
    shutil.copy(TSA_ROOT, OUT / "tsa-root.cert.pem")
    for name, data in cases(control).items():
        (OUT / name).write_bytes(data)

    manifest_cases = [{"file": "control-valid.pdf", "expected": "valid control"}]
    manifest_cases.extend(
        {
            "file": name,
            "expected": "EU-DSS TOTAL_FAILED / FORMAT_FAILURE",
        }
        for name in sorted(cases(control))
    )
    manifest = {
        "source": str(CONTROL_PDF),
        "trustAnchors": ["root.cert.pem", "tsa-root.cert.pem"],
        "cases": manifest_cases,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (OUT / "README.md").write_text(
        """# PDF Model Gap Fixtures

Generated on 2026-05-27 from:

- `/Users/cristian/Development/pdf-generator/output/20260523-190456/control-valid.pdf`
- `scripts/generate_pdf_model_gap_fixtures.py`

These fixtures target remaining PDF/PAdES model gaps before implementing more
validator changes. They are intentionally limited to cases EU-DSS 6.2 confirmed
as malformed under the pdf-generator trust-anchor harness.

EU-DSS command:

```sh
java -cp /Users/cristian/Development/signed_pdfs/dss-validator/target/dss-corpus-validator-jar-with-dependencies.jar \\
  ValidatePdfgen \\
  rust/sd_trust_kit/tests/fixtures/pdf_model_gaps \\
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
""",
        encoding="utf-8",
    )
    print(OUT)


if __name__ == "__main__":
    main()
