use sd_trust_kit::{EuTrustedListCache, Status, Step, StepKind, Verdict, VerificationOptions};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn trusted_list_cache_can_supply_signer_and_timestamp_anchors() {
    let cache = trusted_list_cache();
    let options = VerificationOptions {
        signer_trust_anchor_sets: cache.signer_trust_anchor_sets(),
        timestamp_trust_anchor_sets: cache.timestamp_trust_anchor_sets(),
        ..VerificationOptions::default()
    };

    let pdf = fs::read(corpus_pdf("0013.pdf")).expect("read corpus PDF");
    let report = sd_trust_kit::verify_pdf_with_options(&pdf, &options);
    let steps = &report.signatures[0].steps;

    assert_eq!(
        signature_step(steps, StepKind::SignerCertificateChain).status,
        Status::Ok
    );
    assert_eq!(
        signature_step(steps, StepKind::TsaCertificateChain).status,
        Status::Ok
    );
}

#[test]
fn trusted_list_cache_validates_zealid_with_escaped_pdf_modification_date() {
    let cache = trusted_list_cache();
    let options = VerificationOptions {
        signer_trust_anchor_sets: cache.signer_trust_anchor_sets(),
        timestamp_trust_anchor_sets: cache.timestamp_trust_anchor_sets(),
        ..VerificationOptions::default()
    };

    let pdf = fs::read(repo_root().join("validation-corpus/zealid.pdf")).expect("read ZealiD PDF");
    let report = sd_trust_kit::verify_pdf_with_options(&pdf, &options);
    let signature = &report.signatures[0];

    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(signature.verdict, Verdict::Valid);
    assert_eq!(signature.signing_time.as_deref(), Some("D:20260603115804Z"));
    assert_eq!(
        signature_step(&signature.steps, StepKind::SignerCertificateChain).status,
        Status::Ok
    );
    assert_eq!(
        signature_step(&signature.steps, StepKind::TsaCertificateChain).status,
        Status::Ok
    );
}

#[test]
fn trusted_list_cache_filters_match_swift_snapshot_semantics() {
    let cache = trusted_list_cache();
    let validation_time = cache.fetched_at_unix_time();

    assert_eq!(cache.entries.len(), 7_737);
    assert_eq!(
        cache
            .trusted_signer_anchors_at_unix_time(validation_time)
            .len(),
        1_000
    );
    assert_eq!(
        cache
            .trusted_timestamp_anchors_at_unix_time(validation_time)
            .len(),
        1_161
    );
}

fn signature_step(steps: &[Step], kind: StepKind) -> &Step {
    steps
        .iter()
        .find(|step| step.kind == kind)
        .unwrap_or_else(|| panic!("missing step {kind:?}"))
}

fn trusted_list_cache() -> EuTrustedListCache {
    EuTrustedListCache::from_json_slice(include_bytes!(
        "fixtures/eu_trusted_list/trusted-certificates-v2.json"
    ))
    .expect("trusted-list cache")
}

fn corpus_pdf(file: &str) -> PathBuf {
    reference_repo_root().join("testpdfs/sources").join(file)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root")
        .to_path_buf()
}

fn reference_repo_root() -> PathBuf {
    if let Ok(path) = std::env::var("CEISIGN_REPO_DIR") {
        return PathBuf::from(path);
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(|root| root.join("CEISign"));
    if let Some(path) = sibling.filter(|path| path.is_dir()) {
        return path;
    }
    PathBuf::from("/Users/cristian/Development/CEISign")
}
