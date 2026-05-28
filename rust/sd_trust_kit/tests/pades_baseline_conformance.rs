use sd_trust_kit::{Status, StepKind, ValidationSubIndication, Verdict};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn dss_multiple_signer_infos_are_chain_inconclusive_offline() {
    let Some(report) = verify_signed_pdfs_case("sources/dss/pdf-double-signer-info.pdf") else {
        return;
    };

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures[0].steps.iter().any(|step| {
        step.kind == StepKind::PadesBaselineRequirements && step.status == Status::Fail
    }));
}

#[test]
fn legacy_adobe_rejects_encapsulated_cms_content_by_crypto_result() {
    let Some(report) = verify_signed_pdfs_case("sources/pyhanko/pdf-sig-with-econtent.pdf") else {
        return;
    };

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::SignatureCryptoFailure
    );
}

#[test]
fn legacy_adobe_without_signed_attributes_is_chain_inconclusive_offline() {
    let Some(report) = verify_signed_pdfs_case("sources/pyhanko/sig-no-signed-attrs.pdf") else {
        return;
    };

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures[0].steps.iter().any(|step| {
        step.kind == StepKind::SignatureVerifyContent && step.status == Status::Ok
    }));
}

#[test]
fn legacy_adobe_without_signed_attributes_can_be_chain_inconclusive() {
    let Some(report) = verify_signed_pdfs_case("sources/dss/pkcs7-no-message-digest.pdf") else {
        return;
    };

    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
}

#[test]
fn dss_multisignature_fixture_does_not_treat_later_signatures_as_modification() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-cookbook/snippets/25sigs.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 24);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert!(
        report.signatures.iter().all(|signature| {
            signature.steps.iter().all(|step| {
                step.detail != "Later validation-data revision changed an existing PDF object"
            })
        }),
        "later signature revisions were misclassified as validation-data object rewrites"
    );
}

#[test]
fn dss_open_password_protected_fixture_reports_error() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-cookbook/snippets/open_protected.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Error);
    assert!(report.signatures.is_empty());
    assert!(report
        .steps
        .iter()
        .any(|step| { step.detail == "Encrypted PDF cannot be inspected without a password" }));
}

#[test]
fn dss_permission_protected_unsigned_fixture_reports_no_signatures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/protected/edition_protected_none.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::NoSignatures);
    assert!(report.signatures.is_empty());
}

#[test]
fn dss_legacy_adobe_detached_signature_without_ess_attr_is_not_format_failure() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path =
        root.join("dss-pades/protected/edition_protected_signing_allowed_with_field_signed.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(
        report.signatures.iter().all(|signature| {
            signature.steps.iter().all(|step| {
                !step
                    .detail
                    .starts_with("signing-certificate or signing-certificate-v2")
            })
        }),
        "legacy adbe.pkcs7.detached signature was treated as a PAdES baseline format failure"
    );
}

#[test]
fn dss_legacy_adobe_detached_signature_without_signed_attrs_is_chain_inconclusive() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/DSS-1683.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(
        report.signatures.iter().all(|signature| {
            signature.steps.iter().all(|step| {
                step.detail != "PAdES Baseline requires signed attributes"
            })
        }),
        "legacy adbe.pkcs7.detached signature was treated as a PAdES baseline signature"
    );
}

#[test]
fn dss_usage_rights_signature_is_not_reported_as_document_signature() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/DSS-2601.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
}

#[test]
fn dss_ltv_tail_metadata_refresh_is_not_document_modification() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/DSS-2821.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures.iter().all(|signature| {
        signature
            .steps
            .iter()
            .all(|step| step.kind != StepKind::DocumentModifiedAfterSigning)
    }));
}

#[test]
fn dss_ltv_tail_catalog_version_extension_is_not_document_modification() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/dss-2554/fieldmdp-exclude-signed.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures.iter().all(|signature| {
        signature
            .steps
            .iter()
            .all(|step| step.kind != StepKind::DocumentModifiedAfterSigning)
    }));
}

#[test]
fn dss_ad_rb_reports_second_signature_crypto_failure() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/AD-RB.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 2);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::SignatureCryptoFailure
    );

    let second = &report.signatures[1];
    assert_eq!(second.verdict, Verdict::Invalid);
    assert!(second.steps.iter().any(|step| {
        step.kind == StepKind::SignatureVerifySignedAttributes && step.status == Status::Fail
    }));
}

#[test]
fn dss_signature_with_signature_oid_as_digest_algorithm_is_hash_failure() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/Signature-P-HU_NET-2.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::HashFailure
    );
}

#[test]
fn dss_brainpool_plain_ecdsa_signature_verifies() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path =
        root.join("dss-pades/validation/dss-PLAIN-ECDSA/TeleSec_PKS_eIDAS_QES_CA_1-baseline-b.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures[0].steps.iter().any(|step| {
        step.kind == StepKind::SignatureVerifySignedAttributes && step.status == Status::Ok
    }));
}

#[test]
fn dss_distinct_signatures_with_same_byte_range_are_not_deduplicated() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/hello_signed_INCSAVE_signed_EDITED.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 2);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::FormatFailure
    );
}

#[test]
fn dss_missing_pdf_header_reports_error_even_with_signature_dictionary() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/malformed-pades.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Error);
    assert!(report.signatures.is_empty());
}

#[test]
fn dss_cms_without_certificates_is_inconclusive() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/pades-bes-no-certificates.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::SigningCertificateNotFound
    );
}

#[test]
fn dss_pades_baseline_format_problem_is_chain_inconclusive_when_untrusted_offline() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/pades-enveloping-cms.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures[0].steps.iter().any(|step| {
        step.kind == StepKind::PadesBaselineRequirements && step.status == Status::Fail
    }));
}

#[test]
fn dss_empty_encapsulated_content_is_crypto_failure() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/pades-enveloping-empty-bytes-cms.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::SignatureCryptoFailure
    );
}

#[test]
fn dss_parser_exceptions_are_reported_as_errors() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    for relative in [
        "dss-pades/validation/pades-level-b-sig-policy-invalid-digest-algo.pdf",
        "dss-pades/validation/pades-ocsp-archiveCutOff-invalid.pdf",
    ] {
        let path = root.join(relative);
        let data =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let report = sd_trust_kit::verify_pdf(&data);

        assert_eq!(report.verdict, Verdict::Error, "{relative}");
    }
}

#[test]
fn dss_untrusted_signer_chain_dominates_bad_document_timestamp_evidence() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    for relative in [
        "dss-pades/validation/pades-lta-copied-doctst.pdf",
        "dss-pades/validation/pades-t-duplicated-doctst.pdf",
    ] {
        let path = root.join(relative);
        let data =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let report = sd_trust_kit::verify_pdf(&data);

        assert_eq!(report.verdict, Verdict::Inconclusive, "{relative}");
        assert_eq!(
            report.standards.sub_indication,
            ValidationSubIndication::CertificateChainGeneralFailure,
            "{relative}"
        );
    }
}

#[test]
fn dss_vri_tail_and_legacy_sha1_digest_are_inconclusive_offline() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    for relative in [
        "dss-pades/validation/test-with-vri.pdf",
        "dss-pades/validation/wrong-digest-algo.pdf",
    ] {
        let path = root.join(relative);
        let data =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let report = sd_trust_kit::verify_pdf(&data);

        assert_eq!(report.verdict, Verdict::Inconclusive, "{relative}");
    }
}

#[test]
fn dss_empty_signature_placeholders_report_no_signatures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    for relative in [
        "dss-pades/validation/pdf-with-empty-sig.pdf",
        "dss-pades/validation/pdf-with-two-empty-sigs.pdf",
        "dss-pades/validation/pades_opposite_infinite_loop.pdf",
    ] {
        let path = root.join(relative);
        let data =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let report = sd_trust_kit::verify_pdf(&data);

        assert_eq!(report.verdict, Verdict::NoSignatures, "{relative}");
        assert!(report.signatures.is_empty(), "{relative}");
    }
}

#[test]
fn dss_out_of_bounds_signature_without_field_cycle_is_format_failure() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/pades_infinite_loop.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::FormatFailure
    );
}

#[test]
fn dss_timestamp_only_pdf_reports_no_document_signatures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/timestamped-fields.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::NoSignatures);
    assert!(report.signatures.is_empty());
}

#[test]
fn dss_signed_page_count_changes_are_format_failures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    for relative in [
        "dss-pades/validation/pdf-removed-pages.pdf",
        "dss-pades/validation/pdf-signed-added-page.pdf",
    ] {
        let path = root.join(relative);
        let data =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let report = sd_trust_kit::verify_pdf(&data);

        assert_eq!(report.verdict, Verdict::Invalid, "{relative}");
        assert_eq!(
            report.standards.sub_indication,
            ValidationSubIndication::DocumentModifiedAfterSigning,
            "{relative}"
        );
        assert!(report.signatures[0].steps.iter().any(|step| {
            step.kind == StepKind::DocumentModifiedAfterSigning
                && step.detail == "The number of pages changed after the signed revision"
        }));
    }
}

#[test]
fn dss_signature_shadow_copy_is_document_modification() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/pdf-spoofing-attack.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::DocumentModifiedAfterSigning
    );
}

#[test]
fn dss_untrusted_signer_chain_dominates_bad_signature_timestamp() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/TestToSignPDFSHA256_TST_SIG_NOT_FOUND.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.signatures.len(), 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::CertificateChainGeneralFailure
    );
    assert!(report.signatures[0].steps.iter().any(|step| {
        step.kind == StepKind::TsaSignatureVerify && step.status == Status::Fail
    }));
}

#[test]
fn dss_bad_encoded_cms_fixture_reports_no_signatures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/validation/BadEncodedCMS.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::NoSignatures);
    assert!(report.signatures.is_empty());
    assert!(report.steps.iter().any(|step| {
        step.status == Status::Ok
            && step.detail == "PDF parsed; no usable signature dictionaries found"
    }));
}

#[test]
fn dss_corrupted_unsigned_fixture_reports_error() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/EmptyPage-corrupted.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::Error);
    assert!(report.signatures.is_empty());
    assert!(report
        .steps
        .iter()
        .any(|step| step.detail == "PDF page tree is missing or malformed"));
}

#[test]
fn dss_valid_unsigned_fixture_reports_no_signatures() {
    let Some(root) = eu_dss_fixture_root() else {
        eprintln!("skipping EU-DSS fixture-backed test; run fixture ingestion to enable");
        return;
    };
    let path = root.join("dss-pades/EmptyPage.pdf");
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let report = sd_trust_kit::verify_pdf(&data);

    assert_eq!(report.verdict, Verdict::NoSignatures);
    assert!(report.signatures.is_empty());
}

fn verify_signed_pdfs_case(relative: &str) -> Option<sd_trust_kit::ValidationReport> {
    let Some(root) = signed_pdfs_root() else {
        eprintln!("skipping signed_pdfs-backed test; set SIGNED_PDFS_ROOT to enable");
        return None;
    };
    let path = root.join(relative);
    let data = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Some(sd_trust_kit::verify_pdf(&data))
}

fn eu_dss_fixture_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("EU_DSS_FIXTURE_ROOT") {
        return Some(PathBuf::from(path));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate should live under rust/sd_trust_kit")
        .join(
            "validation-corpus/eu-dss-fixtures/d9473b8efea72fd5754623fa92bb9311f2b005c5/resources",
        );
    root.is_dir().then_some(root)
}

fn signed_pdfs_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SIGNED_PDFS_ROOT") {
        return Some(PathBuf::from(path));
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate should live under rust/sd_trust_kit")
        .join("signed_pdfs");
    sibling.is_dir().then_some(sibling)
}
