#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_WORK_ROOT = REPO / "validation-corpus" / "eu-dss-fixtures"
DEFAULT_DSS_REPO = "https://github.com/esig/dss.git"
DEFAULT_DSS_REF = "d9473b8efea72fd5754623fa92bb9311f2b005c5"
DEFAULT_DSS_VERSION = "6.2"

VALIDATION_EXTENSIONS = {
    ".asice",
    ".asics",
    ".bdoc",
    ".cms",
    ".csig",
    ".ddoc",
    ".edoc",
    ".p7m",
    ".p7s",
    ".pdf",
    ".pkcs7",
    ".sce",
    ".scs",
    ".xades",
    ".xml",
}

ALWAYS_MIRROR_EXTENSIONS = VALIDATION_EXTENSIONS | {
    ".bin",
    ".cer",
    ".crt",
    ".crl",
    ".der",
    ".ers",
    ".jks",
    ".json",
    ".p12",
    ".pem",
    ".properties",
    ".tsr",
    ".tst",
    ".txt",
    ".zip",
}


JAVA_NORMALIZER = r"""
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class NormalizeDssFixtures {
  public static void main(String[] args) throws Exception {
    Path resourceRoot = Paths.get(args[0]).toAbsolutePath();
    Path selectedTsv = Paths.get(args[1]).toAbsolutePath();
    Path outputJsonl = Paths.get(args[2]).toAbsolutePath();
    Files.createDirectories(outputJsonl.getParent());

    CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
    CertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setTrustedCertSources(trust);
    verifier.setCheckRevocationForUntrustedChains(false);
    IgnoreDataLoader offlineLoader = new IgnoreDataLoader();
    verifier.setAIASource(new DefaultAIASource(offlineLoader));
    verifier.setCrlSource(new OnlineCRLSource(offlineLoader));
    verifier.setOcspSource(new OnlineOCSPSource(offlineLoader));

    try (BufferedReader in = new BufferedReader(new InputStreamReader(Files.newInputStream(selectedTsv), StandardCharsets.UTF_8));
         BufferedWriter out = Files.newBufferedWriter(outputJsonl, StandardCharsets.UTF_8)) {
      String header = in.readLine();
      String line;
      int n = 0;
      while ((line = in.readLine()) != null) {
        if (line.isBlank()) continue;
        String[] cols = line.split("\\t", -1);
        String rel = cols[0];
        String kind = cols.length > 1 ? cols[1] : "";
        String module = cols.length > 2 ? cols[2] : "";
        Path file = resourceRoot.resolve(rel);
        Result result = validate(file, verifier);
        String json = "{"
          + jsonField("resource", rel) + ","
          + jsonField("module", module) + ","
          + jsonField("kind", kind) + ","
          + jsonField("sha256", sha256(file)) + ","
          + "\"bytes\":" + Files.size(file) + ","
          + jsonField("dss_aggregate", result.aggregate) + ","
          + "\"signature_count\":" + result.signatureCount + ","
          + "\"valid_signature_count\":" + result.validSignatureCount + ","
          + jsonArray("indications", result.indications) + ","
          + jsonArray("sub_indications", result.subIndications) + ","
          + jsonArray("valid_flags", result.validFlags) + ","
          + jsonField("error", result.error)
          + "}";
        out.write(json);
        out.newLine();
        n++;
        if (n % 100 == 0) {
          System.err.printf(Locale.ROOT, "normalized %d fixtures%n", n);
        }
      }
    }
  }

  private static Result validate(Path file, CertificateVerifier verifier) {
    Result result = new Result();
    try {
      DSSDocument document = new FileDocument(file.toFile());
      SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
      validator.setCertificateVerifier(verifier);
      Reports reports = validator.validateDocument();
      SimpleReport simple = reports.getSimpleReport();
      List<String> ids = simple.getSignatureIdList();
      result.signatureCount = ids.size();
      result.validSignatureCount = simple.getValidSignaturesCount();
      boolean anyFailed = false;
      boolean anyIndeterminate = false;
      boolean allValid = !ids.isEmpty();
      for (String id : ids) {
        Indication indication = simple.getIndication(id);
        SubIndication subIndication = simple.getSubIndication(id);
        boolean valid = simple.isValid(id);
        String indicationName = indication == null ? "" : indication.name();
        result.indications.add(indicationName);
        result.subIndications.add(subIndication == null ? "" : subIndication.name());
        result.validFlags.add(Boolean.toString(valid));
        allValid &= valid;
        if (indicationName.contains("FAILED")) anyFailed = true;
        if (indicationName.contains("INDETERMINATE")) anyIndeterminate = true;
      }
      if (ids.isEmpty()) result.aggregate = "NO_SIGNATURES";
      else if (allValid) result.aggregate = "Valid";
      else if (anyFailed) result.aggregate = "Invalid";
      else if (anyIndeterminate) result.aggregate = "Inconclusive";
      else result.aggregate = "Unknown";
    } catch (Throwable t) {
      result.aggregate = "Error";
      result.error = t.getClass().getSimpleName() + ":" + clean(t.getMessage());
    }
    return result;
  }

  private static String sha256(Path p) throws Exception {
    byte[] data = Files.readAllBytes(p);
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) sb.append(String.format("%02x", b));
    return sb.toString();
  }

  private static String clean(String value) {
    if (value == null) return "";
    return value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
  }

  private static String jsonField(String key, String value) {
    return quote(key) + ":" + quote(value == null ? "" : value);
  }

  private static String jsonArray(String key, List<String> values) {
    StringBuilder sb = new StringBuilder();
    sb.append(quote(key)).append(":[");
    for (int i = 0; i < values.size(); i++) {
      if (i > 0) sb.append(",");
      sb.append(quote(values.get(i)));
    }
    sb.append("]");
    return sb.toString();
  }

  private static String quote(String value) {
    StringBuilder sb = new StringBuilder();
    sb.append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b"); break;
        case '\f': sb.append("\\f"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) sb.append(String.format("\\u%04x", (int)c));
          else sb.append(c);
      }
    }
    sb.append('"');
    return sb.toString();
  }

  static class Result {
    String aggregate = "";
    int signatureCount = 0;
    int validSignatureCount = 0;
    ArrayList<String> indications = new ArrayList<>();
    ArrayList<String> subIndications = new ArrayList<>();
    ArrayList<String> validFlags = new ArrayList<>();
    String error = "";
  }
}
"""


POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>local</groupId>
  <artifactId>dss-fixture-normalizer</artifactId>
  <version>1.0</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <dss.version>{dss_version}</dss.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-pades-pdfbox</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-cades</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-xades</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-asic-cades</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-asic-xades</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-service</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-validation</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-utils-apache-commons</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>eu.europa.ec.joinup.sd-dss</groupId>
      <artifactId>dss-crl-parser-x509crl</artifactId>
      <version>${{dss.version}}</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-nop</artifactId>
      <version>2.0.16</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-dependency-plugin</artifactId>
        <version>3.8.1</version>
      </plugin>
    </plugins>
  </build>
</project>
"""


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, cwd=cwd, check=check, text=True)


def capture(cmd: list[str], cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, text=True).strip()


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def paths_for(ref: str, work_root: Path) -> dict[str, Path]:
    return {
        "base": work_root / ref,
        "checkout": work_root / ref / "checkout",
        "mirror": work_root / ref / "resources",
        "reports": work_root / ref / "reports",
        "normalizer": work_root / ref / "normalizer",
    }


def ensure_checkout(args: argparse.Namespace) -> Path:
    paths = paths_for(args.ref, args.work_root)
    checkout = paths["checkout"]
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", "--no-checkout", args.repo_url, str(checkout)])
        run(["git", "sparse-checkout", "init", "--no-cone"], cwd=checkout)
        sparse = checkout / ".git" / "info" / "sparse-checkout"
        sparse.write_text(
            "/*/src/test/resources/**\n"
            "/*/src/test/java/**\n",
            encoding="utf-8",
        )
    run(["git", "fetch", "--depth", "1", "origin", args.ref], cwd=checkout)
    run(["git", "checkout", "--detach", args.ref], cwd=checkout)
    actual = capture(["git", "rev-parse", "HEAD"], cwd=checkout)
    if actual != args.ref:
        print(f"warning: requested {args.ref}, checked out {actual}", file=sys.stderr)
    return checkout


def resource_entries(checkout: Path) -> list[dict[str, object]]:
    resources: list[dict[str, object]] = []
    for path in sorted(checkout.glob("*/src/test/resources/**/*")):
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        module = path.parts[len(checkout.parts)]
        rel_checkout = safe_rel(path, checkout)
        rel_resource = f"{module}/{safe_rel(path, checkout / module / 'src' / 'test' / 'resources')}"
        size = path.stat().st_size
        kind = classify_kind(module, rel_resource, ext)
        candidate_reason = candidate_reason_for(module, rel_resource, ext)
        resources.append(
            {
                "module": module,
                "path": rel_resource,
                "checkout_path": rel_checkout,
                "extension": ext,
                "bytes": size,
                "sha256": sha256(path),
                "kind": kind,
                "candidate": candidate_reason is not None,
                "candidate_reason": candidate_reason,
            }
        )
    return resources


def classify_kind(module: str, rel_resource: str, ext: str) -> str:
    if ext == ".pdf":
        return "pades"
    if ext in {".p7m", ".p7s", ".pkcs7", ".cms", ".csig"}:
        return "cades"
    if ext in {".asice", ".asics", ".sce", ".scs", ".bdoc", ".ddoc", ".edoc"}:
        return "asic"
    if ext in {".xml", ".xades"}:
        if "xades" in module or "xades" in rel_resource.lower():
            return "xades"
        if "asic" in module:
            return "asic-support"
        return "xml"
    return ext.lstrip(".") or "unknown"


def candidate_reason_for(module: str, rel_resource: str, ext: str) -> str | None:
    lower = rel_resource.lower()
    if ext == ".pdf":
        return "pdf"
    if ext in {".p7m", ".p7s", ".pkcs7", ".cms", ".csig"}:
        return "cades-container"
    if ext in {".asice", ".asics", ".sce", ".scs", ".bdoc", ".ddoc", ".edoc"}:
        return "asic-container"
    if ext in {".xml", ".xades"} and "/validation/" in lower and ("xades" in module or "xades" in lower):
        return "xades-validation-xml"
    return None


def mirror_resources(checkout: Path, mirror: Path, resources: list[dict[str, object]]) -> None:
    if mirror.exists():
        shutil.rmtree(mirror)
    mirror.mkdir(parents=True)
    for entry in resources:
        ext = str(entry["extension"])
        if ext not in ALWAYS_MIRROR_EXTENSIONS and not entry["candidate"]:
            continue
        src = checkout / str(entry["checkout_path"])
        dest = mirror / str(entry["path"])
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


RESOURCE_REF_RE = re.compile(
    r"(?:getResource(?:AsStream)?|new\s+File|FileDocument|InMemoryDocument)\s*\(\s*\"([^\"]+)\""
    r"|\"((?:src/test/resources|/validation|/signature|/signable|/timestamp|/certs|/revocation)[^\"]+)\""
)
JAVA_TYPE_RE = re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")


def java_references(checkout: Path) -> dict[str, list[str]]:
    refs: dict[str, set[str]] = defaultdict(set)
    for java in sorted(checkout.glob("*/src/test/java/**/*.java")):
        module = java.parts[len(checkout.parts)]
        text = java.read_text(encoding="utf-8", errors="ignore")
        java_rel = safe_rel(java, checkout)
        for normalized in extract_references(module, text):
            refs[normalized].add(java_rel)
    return {k: sorted(v) for k, v in sorted(refs.items())}


def java_test_index(checkout: Path) -> list[dict[str, object]]:
    tests: list[dict[str, object]] = []
    for java in sorted(checkout.glob("*/src/test/java/**/*.java")):
        module = java.parts[len(checkout.parts)]
        text = java.read_text(encoding="utf-8", errors="ignore")
        refs = extract_references(module, text)
        types = sorted(set(JAVA_TYPE_RE.findall(text)))
        if not refs and not types:
            continue
        tests.append(
            {
                "module": module,
                "path": safe_rel(java, checkout),
                "classes": types,
                "resource_references": refs,
            }
        )
    return tests


def extract_references(module: str, text: str) -> list[str]:
    refs: set[str] = set()
    for match in RESOURCE_REF_RE.finditer(text):
        raw = match.group(1) or match.group(2)
        if not raw or "${" in raw:
            continue
        normalized = normalize_reference(module, raw)
        if normalized:
            refs.add(normalized)
    return sorted(refs)


def normalize_reference(module: str, raw: str) -> str | None:
    raw = raw.strip()
    raw = raw.removeprefix("classpath:")
    raw = raw.removeprefix("/")
    if raw.startswith("src/test/resources/"):
        return f"{module}/{raw[len('src/test/resources/'):]}"
    if raw.startswith("src/test/resources"):
        return f"{module}/{raw[len('src/test/resources'):].lstrip('/')}"
    if raw.startswith(("validation/", "signable/", "timestamp/", "certs/", "revocation/", "signature")):
        return f"{module}/{raw}"
    return None


def write_index(args: argparse.Namespace) -> None:
    checkout = ensure_checkout(args)
    paths = paths_for(args.ref, args.work_root)
    resources = resource_entries(checkout)
    refs = java_references(checkout)
    tests = java_test_index(checkout)
    for entry in resources:
        entry["referenced_by"] = refs.get(str(entry["path"]), [])
    mirror_resources(checkout, paths["mirror"], resources)
    selected = select_candidates(resources, args)
    write_json(paths["base"] / "index.json", {"dss_repo": args.repo_url, "dss_ref": args.ref, "resources": resources})
    write_json(paths["base"] / "test-resource-references.json", refs)
    write_json(paths["base"] / "java-test-index.json", {"tests": tests})
    write_json(paths["base"] / "selected-fixtures.json", {"selection": selection_meta(args), "fixtures": selected})
    write_selected_tsv(paths["base"] / "selected-fixtures.tsv", selected)
    write_summary(paths["base"] / "index-summary.json", resources, selected)
    print(paths["base"])


def select_candidates(resources: list[dict[str, object]], args: argparse.Namespace) -> list[dict[str, object]]:
    formats = set(args.formats.split(",")) if args.formats else {"pades", "cades", "xades", "asic"}
    selected = []
    for entry in resources:
        if not entry["candidate"]:
            continue
        kind = str(entry["kind"])
        if kind == "asic-support":
            continue
        if kind not in formats:
            continue
        if args.max_bytes is not None and int(entry["bytes"]) > args.max_bytes:
            continue
        selected.append(entry)
    if args.limit:
        selected = selected[: args.limit]
    return selected


def selection_meta(args: argparse.Namespace) -> dict[str, object]:
    return {"formats": args.formats, "limit": args.limit, "max_bytes": args.max_bytes}


def write_selected_tsv(path: Path, selected: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("resource\tkind\tmodule\tbytes\tsha256\n")
        for entry in selected:
            f.write(
                f"{entry['path']}\t{entry['kind']}\t{entry['module']}\t{entry['bytes']}\t{entry['sha256']}\n"
            )


def write_summary(path: Path, resources: list[dict[str, object]], selected: list[dict[str, object]]) -> None:
    summary = {
        "resource_count": len(resources),
        "candidate_count": sum(1 for r in resources if r["candidate"]),
        "selected_count": len(selected),
        "resources_by_extension": Counter(str(r["extension"]) or "<none>" for r in resources),
        "resources_by_kind": Counter(str(r["kind"]) for r in resources),
        "selected_by_kind": Counter(str(r["kind"]) for r in selected),
        "selected_by_module": Counter(str(r["module"]) for r in selected),
    }
    write_json(path, summary)


def prepare_normalizer(args: argparse.Namespace) -> Path:
    paths = paths_for(args.ref, args.work_root)
    normalizer = paths["normalizer"]
    src = normalizer / "src" / "main" / "java"
    src.mkdir(parents=True, exist_ok=True)
    (normalizer / "pom.xml").write_text(POM.format(dss_version=args.dss_version), encoding="utf-8")
    (src / "NormalizeDssFixtures.java").write_text(JAVA_NORMALIZER.strip() + "\n", encoding="utf-8")
    run(["mvn", "-q", "compile", "dependency:build-classpath", "-Dmdep.outputFile=classpath.txt"], cwd=normalizer)
    cp = (normalizer / "classpath.txt").read_text(encoding="utf-8").strip()
    classes = normalizer / "target" / "classes"
    classpath = f"{classes}{os.pathsep}{cp}"
    (normalizer / "runtime-classpath.txt").write_text(classpath + "\n", encoding="utf-8")
    return normalizer


def normalize(args: argparse.Namespace) -> None:
    write_index(args)
    paths = paths_for(args.ref, args.work_root)
    normalizer = prepare_normalizer(args)
    reports = paths["reports"]
    reports.mkdir(parents=True, exist_ok=True)
    output = reports / "dss-normalized.jsonl"
    classpath = (normalizer / "runtime-classpath.txt").read_text(encoding="utf-8").strip()
    java_cmd = [
        "java",
        "-cp",
        classpath,
        "NormalizeDssFixtures",
        str(paths["mirror"]),
        str(paths["base"] / "selected-fixtures.tsv"),
        str(output),
    ]
    if args.sandbox and shutil.which("sandbox-exec"):
        sandbox = paths["base"] / "no-network.sb"
        sandbox.write_text("(version 1)\n(allow default)\n(deny network*)\n", encoding="utf-8")
        java_cmd = ["sandbox-exec", "-f", str(sandbox)] + java_cmd
    run(java_cmd)
    build_normalized_manifest(paths["base"], output, args)
    print(output)


def build_normalized_manifest(base: Path, jsonl: Path, args: argparse.Namespace) -> None:
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = {
        "normalized_count": len(rows),
        "by_kind": Counter(row["kind"] for row in rows),
        "by_aggregate": Counter(row["dss_aggregate"] for row in rows),
        "by_error": Counter(row["error"].split(":", 1)[0] for row in rows if row.get("error")),
        "by_sub_indication": Counter(
            sub for row in rows for sub in row.get("sub_indications", []) if sub
        ),
    }
    manifest = {
        "source": {
            "dss_repo": args.repo_url,
            "dss_ref": args.ref,
            "dss_version": args.dss_version,
            "normalization": "EU-DSS offline, no network, IgnoreDataLoader for AIA/CRL/OCSP, empty trusted certificate source",
        },
        "summary": summary,
        "fixtures": rows,
    }
    write_json(base / "normalized-manifest.json", manifest)
    write_json(base / "normalized-summary.json", summary)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mirror and normalize upstream EU-DSS test fixtures.")
    parser.add_argument("command", choices=["index", "normalize"])
    parser.add_argument("--repo-url", default=DEFAULT_DSS_REPO)
    parser.add_argument("--ref", default=DEFAULT_DSS_REF)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--dss-version", default=DEFAULT_DSS_VERSION)
    parser.add_argument("--formats", default="pades,cades,xades,asic")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-bytes", type=int, default=None)
    parser.add_argument("--sandbox", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.work_root = args.work_root.resolve()
    if args.command == "index":
        write_index(args)
    elif args.command == "normalize":
        normalize(args)


if __name__ == "__main__":
    main()
