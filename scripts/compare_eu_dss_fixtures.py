#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_REF = "d9473b8efea72fd5754623fa92bb9311f2b005c5"
DEFAULT_BASE = REPO / "validation-corpus" / "eu-dss-fixtures" / DEFAULT_REF
DEFAULT_BIN = REPO / "rust" / "sd_trust_kit" / "target" / "release" / "sd-trust-validate"


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_dss(value: str) -> str:
    if value == "Valid":
        return "valid"
    if value == "Invalid":
        return "invalid"
    if value == "Inconclusive":
        return "inconclusive"
    if value == "NO_SIGNATURES":
        return "no_signatures"
    if value == "Error":
        return "error"
    return value.lower() or "unknown"


def canonical_sdtrustkit(value: str) -> str:
    lowered = value.lower()
    if lowered in {"nosignatures", "no_signatures", "no-signatures"}:
        return "no_signatures"
    return lowered or "unknown"


def run_sdtrustkit(binary: Path, path: Path, timeout: float) -> dict[str, object]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(binary), str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        elapsed = (time.perf_counter() - started) * 1000
        return {
            "supported": True,
            "exit_code": None,
            "ms": round(elapsed, 3),
            "aggregate": "timeout",
            "verdict": "",
            "signature_count": 0,
            "standards_indication": "",
            "standards_sub_indication": "",
            "error": f"TimeoutExpired:{error}",
            "report": None,
        }

    elapsed = (time.perf_counter() - started) * 1000
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    report = None
    parse_error = ""
    if stdout:
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as error:
            parse_error = f"JSONDecodeError:{error}"

    verdict = str(report.get("verdict", "")) if isinstance(report, dict) else ""
    standards = report.get("standards", {}) if isinstance(report, dict) else {}
    signatures = report.get("signatures", []) if isinstance(report, dict) else []
    error = parse_error or stderr
    aggregate = verdict.lower() if completed.returncode == 0 and verdict else "error"

    return {
        "supported": True,
        "exit_code": completed.returncode,
        "ms": round(elapsed, 3),
        "aggregate": aggregate,
        "verdict": verdict,
        "signature_count": len(signatures) if isinstance(signatures, list) else 0,
        "standards_indication": str(standards.get("indication", "")) if isinstance(standards, dict) else "",
        "standards_sub_indication": str(standards.get("subIndication", "")) if isinstance(standards, dict) else "",
        "error": error,
        "report": report,
    }


def unsupported_result(kind: str) -> dict[str, object]:
    return {
        "supported": False,
        "exit_code": None,
        "ms": None,
        "aggregate": "unsupported",
        "verdict": "",
        "signature_count": 0,
        "standards_indication": "",
        "standards_sub_indication": "",
        "error": f"Format not supported by PAdES-only validator: {kind}",
        "report": None,
    }


def compare_row(dss: dict[str, object], sdtrustkit: dict[str, object]) -> dict[str, object]:
    dss_aggregate = str(dss.get("dss_aggregate", ""))
    sdtrustkit_aggregate = str(sdtrustkit.get("aggregate", ""))
    dss_canonical = canonical_dss(dss_aggregate)
    sdtrustkit_canonical = canonical_sdtrustkit(sdtrustkit_aggregate)
    return {
        "resource": dss["resource"],
        "kind": dss["kind"],
        "module": dss["module"],
        "bytes": dss["bytes"],
        "sha256": dss["sha256"],
        "dss": {
            "aggregate": dss_aggregate,
            "canonical": dss_canonical,
            "signature_count": dss.get("signature_count", 0),
            "valid_signature_count": dss.get("valid_signature_count", 0),
            "indications": dss.get("indications", []),
            "sub_indications": dss.get("sub_indications", []),
            "error": dss.get("error", ""),
        },
        "sdtrustkit": {
            "supported": sdtrustkit["supported"],
            "aggregate": sdtrustkit_aggregate,
            "canonical": sdtrustkit_canonical,
            "verdict": sdtrustkit["verdict"],
            "signature_count": sdtrustkit["signature_count"],
            "standards_indication": sdtrustkit["standards_indication"],
            "standards_sub_indication": sdtrustkit["standards_sub_indication"],
            "exit_code": sdtrustkit["exit_code"],
            "ms": sdtrustkit["ms"],
            "error": sdtrustkit["error"],
            "report": sdtrustkit["report"],
        },
        "match": dss_canonical == sdtrustkit_canonical,
        "pair": f"{dss_canonical}->{sdtrustkit_canonical}",
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "resource",
        "kind",
        "bytes",
        "dss",
        "sdtrustkit",
        "match",
        "pair",
        "sdtrustkit_ms",
        "dss_signature_count",
        "sdtrustkit_signature_count",
        "dss_sub_indications",
        "sdtrustkit_sub_indication",
        "sdtrustkit_error",
        "sha256",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "resource": row["resource"],
                    "kind": row["kind"],
                    "bytes": row["bytes"],
                    "dss": row["dss"]["canonical"],
                    "sdtrustkit": row["sdtrustkit"]["canonical"],
                    "match": row["match"],
                    "pair": row["pair"],
                    "sdtrustkit_ms": row["sdtrustkit"]["ms"],
                    "dss_signature_count": row["dss"]["signature_count"],
                    "sdtrustkit_signature_count": row["sdtrustkit"]["signature_count"],
                    "dss_sub_indications": "|".join(row["dss"]["sub_indications"]),
                    "sdtrustkit_sub_indication": row["sdtrustkit"]["standards_sub_indication"],
                    "sdtrustkit_error": row["sdtrustkit"]["error"],
                    "sha256": row["sha256"],
                }
            )


def summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    pades = [row for row in rows if row["kind"] == "pades"]
    supported = [row for row in rows if row["sdtrustkit"]["supported"]]
    unsupported = [row for row in rows if not row["sdtrustkit"]["supported"]]
    mismatches = [row for row in rows if not row["match"]]
    pades_mismatches = [row for row in pades if not row["match"]]
    sdtrustkit_times = [
        float(row["sdtrustkit"]["ms"])
        for row in supported
        if row["sdtrustkit"]["ms"] is not None
    ]
    return {
        "total": len(rows),
        "by_kind": Counter(row["kind"] for row in rows),
        "dss_by_aggregate": Counter(row["dss"]["canonical"] for row in rows),
        "sdtrustkit_by_aggregate": Counter(row["sdtrustkit"]["canonical"] for row in rows),
        "supported_count": len(supported),
        "unsupported_count": len(unsupported),
        "match_count": sum(1 for row in rows if row["match"]),
        "mismatch_count": len(mismatches),
        "pades_count": len(pades),
        "pades_match_count": len(pades) - len(pades_mismatches),
        "pades_mismatch_count": len(pades_mismatches),
        "mismatches_by_pair": Counter(row["pair"] for row in mismatches),
        "pades_mismatches_by_pair": Counter(row["pair"] for row in pades_mismatches),
        "sdtrustkit_ms": {
            "min": round(min(sdtrustkit_times), 3) if sdtrustkit_times else None,
            "max": round(max(sdtrustkit_times), 3) if sdtrustkit_times else None,
            "avg": round(sum(sdtrustkit_times) / len(sdtrustkit_times), 3)
            if sdtrustkit_times
            else None,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare SDTrustKit output against normalized EU-DSS fixture verdicts.")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BIN)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--limit", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base = args.base.resolve()
    binary = args.binary.resolve()
    dss_jsonl = base / "reports" / "dss-normalized.jsonl"
    resource_root = base / "resources"
    reports = base / "reports"
    comparison_jsonl = reports / "sdtrustkit-vs-eu-dss.jsonl"
    comparison_csv = reports / "sdtrustkit-vs-eu-dss.csv"
    summary_json = reports / "sdtrustkit-vs-eu-dss-summary.json"

    if not dss_jsonl.exists():
        raise SystemExit(f"Missing DSS JSONL: {dss_jsonl}")
    if not binary.exists():
        raise SystemExit(f"Missing validator binary: {binary}")

    dss_rows = read_jsonl(dss_jsonl)
    if args.limit:
        dss_rows = dss_rows[: args.limit]

    rows: list[dict[str, object]] = []
    with comparison_jsonl.open("w", encoding="utf-8") as out:
        for idx, dss in enumerate(dss_rows, start=1):
            kind = str(dss.get("kind", ""))
            if kind == "pades":
                sdtrustkit = run_sdtrustkit(binary, resource_root / str(dss["resource"]), args.timeout)
            else:
                sdtrustkit = unsupported_result(kind)
            row = compare_row(dss, sdtrustkit)
            rows.append(row)
            out.write(json.dumps(row, sort_keys=True) + "\n")
            if idx % 50 == 0:
                print(f"compared {idx} fixtures", file=sys.stderr)

    write_csv(comparison_csv, rows)
    summary = summarize(rows)
    write_json(summary_json, summary)
    print(summary_json)
    print(comparison_jsonl)
    print(comparison_csv)


if __name__ == "__main__":
    main()
