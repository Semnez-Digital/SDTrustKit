use sd_trust_kit::{Status, Step, StepKind, VerificationOptions};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn signer_anchor_can_be_supplied_outside_core() {
    let pdf = corpus_pdf("0009.pdf");
    let data = fs::read(pdf).expect("read corpus PDF");

    let without_anchor = sd_trust_kit::verify_pdf(&data);
    let default_signer_chain = signature_step(
        &without_anchor.signatures[0].steps,
        StepKind::SignerCertificateChain,
    );
    assert_eq!(default_signer_chain.status, Status::Warn);

    let with_anchor = sd_trust_kit::verify_pdf_with_options(
        &data,
        &VerificationOptions {
            signer_trust_anchors: vec![fixture_bytes(
                "system_trust_anchors/6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177-entrust-net-ca-2048.der",
            )],
            ..VerificationOptions::default()
        },
    );
    let trusted_signer_chain = signature_step(
        &with_anchor.signatures[0].steps,
        StepKind::SignerCertificateChain,
    );
    assert_eq!(trusted_signer_chain.status, Status::Ok);
    assert_eq!(
        trusted_signer_chain.detail,
        "-> configured signer trust anchor"
    );
}

#[test]
fn app_trust_material_fixtures_are_kept_outside_core() {
    let cei_root = fixture_bytes(
        "app_trust_anchors/b7a766f52218c8083e936f9ab085e97c67671ecd4fd3069b641c638072e44b1d-ro-cei-mai-root-ca.der",
    );
    let sts_root = fixture_bytes(
        "app_trust_anchors/aa53228264e1dd6adb08194fe4c931bd7fd1c54c59b26445409058a8846d4c24-sts-root-g2.der",
    );
    let digicert_pin = fixture_text("app_trust_pins/digicert-tsa-ca-sha256.txt");

    assert_eq!(cei_root.len(), 613);
    assert_eq!(sts_root.len(), 1377);
    assert_eq!(
        digicert_pin,
        "CA0B1554ECD901EA19DCAD8749E9F2648C8D6DFCEA1ADD9D2C2109415BB82CCD"
    );
}

fn signature_step(steps: &[Step], kind: StepKind) -> &Step {
    steps
        .iter()
        .find(|step| step.kind == kind)
        .unwrap_or_else(|| panic!("missing step {kind:?}"))
}

fn fixture_bytes(relative: &str) -> Vec<u8> {
    fs::read(fixture_path(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn fixture_text(relative: &str) -> String {
    fs::read_to_string(fixture_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
        .trim()
        .to_owned()
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
