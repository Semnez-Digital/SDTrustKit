use sd_trust_kit::{
    verify_pdf_including_revocation_with_options, RevocationOptions, Status, StepKind,
    VerificationOptions,
};
use std::path::{Path, PathBuf};

#[test]
fn dss_dictionary_embedded_ocsp_satisfies_signer_revocation_without_external_cache() {
    assert_embedded_ocsp_revocation_ok("dss-pades/validation/pades-ocsp-sign-cert.pdf");
}

#[test]
fn adbe_archival_embedded_ocsp_satisfies_signer_revocation_without_external_cache() {
    assert_embedded_ocsp_revocation_ok("dss-pades/validation/adbe_ocsp_signed.pdf");
}

fn assert_embedded_ocsp_revocation_ok(relative: &str) {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed OCSP test; run fixture ingestion to enable");
        return;
    };
    let path = root.join(relative);
    let pdf = std::fs::read(&path).expect("read EU-DSS PAdES fixture");
    let report = verify_pdf_including_revocation_with_options(
        &pdf,
        &VerificationOptions::default(),
        &RevocationOptions {
            now_unix_seconds: 1_779_530_582.0,
            ..RevocationOptions::default()
        },
    );
    let revocation_steps: Vec<_> = report
        .signatures
        .iter()
        .flat_map(|signature| signature.steps.iter())
        .filter(|step| step.kind == StepKind::RevocationSigner)
        .collect();

    assert!(
        revocation_steps
            .iter()
            .any(|step| step.status == Status::Ok),
        "{relative} did not satisfy signer revocation from embedded OCSP: {:?}",
        revocation_steps
            .iter()
            .map(|step| (&step.status, step.detail.as_str()))
            .collect::<Vec<_>>()
    );
}

fn eu_dss_fixture_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("EU_DSS_FIXTURE_ROOT") {
        return Some(PathBuf::from(path));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join(
            "validation-corpus/eu-dss-fixtures/d9473b8efea72fd5754623fa92bb9311f2b005c5/resources",
        );
    root.is_dir().then_some(root)
}
