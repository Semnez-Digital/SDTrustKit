use sd_trust_kit::{
    CrlCache, EuTrustedListCache, OcspCache, RevocationOptions, Status, Step, StepKind, Verdict,
    VerificationOptions,
};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn crl_cache_fixtures_can_mark_signer_revocation_good() {
    let eu_cache = eu_trusted_list_cache();
    let now = eu_cache.fetched_at_unix_time();
    let verification_options = VerificationOptions {
        signer_trust_anchor_sets: eu_cache.signer_trust_anchor_sets(),
        timestamp_trust_anchor_sets: eu_cache.timestamp_trust_anchor_sets(),
        ..VerificationOptions::default()
    };
    let revocation_options = RevocationOptions {
        crl_cache: crl_cache(),
        ocsp_cache: OcspCache::default(),
        now_unix_seconds: now,
    };

    let pdf = fs::read(corpus_pdf("0013.pdf")).expect("read corpus PDF");
    let report = sd_trust_kit::verify_pdf_including_revocation_with_options(
        &pdf,
        &verification_options,
        &revocation_options,
    );
    let steps = &report.signatures[0].steps;

    assert_eq!(
        signature_step(steps, StepKind::RevocationSigner).status,
        Status::Ok
    );
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
}

#[test]
fn crl_cache_fixture_directory_loads_swift_entries() {
    let cache = crl_cache();

    assert_eq!(cache.entries.len(), 20);
    assert!(cache.entries.iter().all(|entry| !entry.der.is_empty()));
    assert!(cache
        .entries
        .iter()
        .all(|entry| entry.cache_key_sha256.len() == 64));
}

fn signature_step(steps: &[Step], kind: StepKind) -> &Step {
    steps
        .iter()
        .find(|step| step.kind == kind)
        .unwrap_or_else(|| panic!("missing step {kind:?}"))
}

fn eu_trusted_list_cache() -> EuTrustedListCache {
    EuTrustedListCache::from_json_slice(include_bytes!(
        "fixtures/eu_trusted_list/trusted-certificates-v2.json"
    ))
    .expect("trusted-list cache")
}

fn crl_cache() -> CrlCache {
    CrlCache::from_directory(fixture_path("crl_cache")).expect("CRL cache")
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

fn corpus_pdf(file: &str) -> PathBuf {
    reference_repo_root().join("testpdfs/sources").join(file)
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
