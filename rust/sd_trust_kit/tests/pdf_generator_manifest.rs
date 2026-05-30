use base64::Engine;
use sd_trust_kit::{CrlCache, CrlCacheEntry, RevocationOptions, Verdict, VerificationOptions};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const FAR_FUTURE_APPLE_REFERENCE_SECONDS: f64 = 4_000_000_000.0;

#[derive(Debug, Deserialize)]
struct ManifestCase {
    file: String,
    category: String,
    case_id: String,
    expected_verifier_result: String,
    crl_url: Option<String>,
    generation_error: Option<String>,
}

#[test]
fn pdf_generator_manifest_matches_expected_outcomes() {
    let Some(output_root) = pdf_generator_output_root() else {
        return;
    };
    let runs = pdf_generator_runs(&output_root);
    assert!(
        !runs.is_empty(),
        "no pdf-generator runs with manifest.json found under {}",
        output_root.display()
    );

    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    for run in runs {
        let manifest_path = run.join("manifest.json");
        let manifest: Vec<ManifestCase> =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("decode manifest");
        let crl_cache = crl_cache_for_manifest(&run, &manifest);
        let revocation_options = RevocationOptions {
            crl_cache,
            now_unix_seconds: now_unix_seconds(),
        };

        for case in manifest {
            if case.generation_error.is_some() {
                continue;
            }
            let pdf_path = run.join(&case.file);
            if !pdf_path.is_file() {
                mismatches.push(format!("{}: manifest PDF is missing", pdf_path.display()));
                continue;
            }

            let data = fs::read(&pdf_path).expect("read generated PDF");
            let options = verification_options_for_case(&run, &case);
            let report = if case.category == "revocation" {
                sd_trust_kit::verify_pdf_including_revocation_with_options(
                    &data,
                    &options,
                    &revocation_options,
                )
            } else {
                sd_trust_kit::verify_pdf_with_options(&data, &options)
            };
            let expected = expected_verdict(&case.expected_verifier_result);
            if report.verdict != expected {
                mismatches.push(format!(
                    "{} [{}]: expected {:?}, got {:?} ({:?}/{:?})",
                    run.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<run>"),
                    case.case_id,
                    expected,
                    report.verdict,
                    report.standards.indication,
                    report.standards.sub_indication
                ));
            }
            checked += 1;
        }
    }

    assert!(checked > 0, "no generated pdf-generator cases were checked");
    assert!(
        mismatches.is_empty(),
        "pdf-generator manifest guardrail found unexpected outcomes:\n{}",
        mismatches.join("\n")
    );
}

fn pdf_generator_output_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PDF_GENERATOR_OUTPUT_ROOT") {
        return Some(PathBuf::from(path));
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live under rust/sd_trust_kit");
    let sibling = workspace_root
        .parent()
        .expect("workspace root has a parent")
        .join("pdf-generator/output");
    if sibling.is_dir() {
        return Some(sibling);
    }

    let combined = workspace_root.join("validation-corpus/combined-pdfs/pdf-generator/output");
    combined.is_dir().then_some(combined)
}

fn pdf_generator_runs(output_root: &Path) -> Vec<PathBuf> {
    let mut runs: Vec<PathBuf> = fs::read_dir(output_root)
        .expect("read pdf-generator output root")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("manifest.json").is_file())
        .collect();
    runs.sort();
    runs
}

fn verification_options_for_case(run: &Path, case: &ManifestCase) -> VerificationOptions {
    let mut options = VerificationOptions::default();
    let signer_root = run.join(&case.case_id).join("root.cert.pem");
    if signer_root.is_file() {
        options.signer_trust_anchors.push(read_pem_der(signer_root));
    }
    let tsa_root = run.join("tsa-root.cert.pem");
    if tsa_root.is_file() {
        options.timestamp_trust_anchors.push(read_pem_der(tsa_root));
    }
    options
}

fn crl_cache_for_manifest(run: &Path, manifest: &[ManifestCase]) -> CrlCache {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for case in manifest {
        if case.category != "revocation" || case.case_id == "crl-unreachable" {
            continue;
        }
        let Some(url) = &case.crl_url else {
            continue;
        };
        let Some(cache_key_sha256) = crl_cache_key_for_url(url) else {
            continue;
        };
        if !seen.insert(cache_key_sha256.clone()) {
            continue;
        }
        let crl_path = run.join(&case.case_id).join("crl/intermediate.crl");
        if !crl_path.is_file() {
            continue;
        }
        entries.push(CrlCacheEntry {
            cache_key_sha256,
            valid_until: FAR_FUTURE_APPLE_REFERENCE_SECONDS,
            der: fs::read(crl_path).expect("read generated CRL"),
        });
    }
    CrlCache { entries }
}

fn crl_cache_key_for_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("https://") {
        &url[8..]
    } else {
        return None;
    };
    if rest.split('/').next().unwrap_or_default().is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(
        format!("https://{rest}").as_bytes(),
    )))
}

fn expected_verdict(expected: &str) -> Verdict {
    match expected {
        "valid" => Verdict::Valid,
        "invalid" => Verdict::Invalid,
        "inconclusive" | "indeterminate" => Verdict::Inconclusive,
        other => panic!("unknown expected verifier result {other}"),
    }
}

fn now_unix_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is after UNIX epoch")
        .as_secs_f64()
}

fn read_pem_der(path: impl AsRef<Path>) -> Vec<u8> {
    let data = fs::read(path.as_ref())
        .unwrap_or_else(|error| panic!("read {}: {error}", path.as_ref().display()));
    let text = String::from_utf8(data).expect("PEM is UTF-8");
    let body = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("decode PEM body")
}
