use base64::Engine;
use sd_trust_kit::{ValidationIndication, ValidationSubIndication, Verdict, VerificationOptions};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn pdf_generator_control_with_generated_trust_is_valid() {
    let report = verify_case("control-valid");

    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(
        report.standards.indication,
        ValidationIndication::TotalPassed
    );
}

#[test]
fn pdf_generator_rejects_wrong_signature_timestamp_content_type() {
    let report = verify_case("ts-wrong-econtenttype");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::TimestampGeneralFailure
    );
}

#[test]
fn pdf_generator_rejects_invalid_signature_timestamp_signature() {
    let report = verify_case("ts-sig-invalid");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::SignatureCryptoFailure
    );
}

#[test]
fn pdf_generator_rejects_signature_timestamp_imprint_mismatch() {
    let report = verify_case("ts-imprint-mismatch");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::TimestampGeneralFailure
    );
}

#[test]
fn pdf_generator_tsa_certificate_out_of_bounds_is_indeterminate() {
    let report = verify_case("ts-gentime-after-tsa-expiry");

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
}

#[test]
fn pdf_generator_tsa_missing_timestamp_eku_is_invalid() {
    let report = verify_case("ts-tsa-no-eku");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CryptographicConstraintsFailure
    );
}

#[test]
fn pdf_generator_expired_b_b_signer_without_poe_is_indeterminate() {
    let report = verify_case("cert-expired");

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::RevocationOutOfBoundsNoPoe
    );
}

#[test]
fn pdf_generator_wrong_signer_eku_is_invalid() {
    let report = verify_case("cert-wrong-eku");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CryptographicConstraintsFailure
    );
}

#[test]
fn pdf_generator_missing_signing_key_usage_is_invalid() {
    let report = verify_case("cert-no-signing-key-usage");

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CryptographicConstraintsFailure
    );
}

fn verify_case(case_id: &str) -> sd_trust_kit::ValidationReport {
    let run = fixture_run_dir();
    let pdf = fs::read(run.join(format!("{case_id}.pdf"))).expect("read generated PDF");
    let mut options = VerificationOptions {
        signer_trust_anchors: vec![read_pem_der(run.join(case_id).join("root.cert.pem"))],
        ..VerificationOptions::default()
    };
    let tsa_root = run.join("tsa-root.cert.pem");
    if tsa_root.is_file() {
        options.timestamp_trust_anchors.push(read_pem_der(tsa_root));
    }
    sd_trust_kit::verify_pdf_with_options(&pdf, &options)
}

fn fixture_run_dir() -> PathBuf {
    if let Ok(path) = std::env::var("PDF_GENERATOR_RUN_DIR") {
        return PathBuf::from(path);
    }
    let sibling_generator = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate should live under rust/sd_trust_kit")
        .join("pdf-generator/output/20260523-190456");
    if sibling_generator.join("manifest.json").is_file() {
        return sibling_generator;
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live under rust/sd_trust_kit")
        .join("validation-corpus/combined-pdfs/pdf-generator/output/20260523-190456")
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
