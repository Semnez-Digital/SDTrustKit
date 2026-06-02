#[cfg(feature = "android-jni")]
mod android_jni;
mod asn1;
mod cms;
mod crypto;
mod eu_trusted_list;
mod ffi;
mod options;
mod pdf;
mod report;
mod revocation;
mod timestamp;
mod trust;

pub use eu_trusted_list::{EuTrustedCertificate, EuTrustedListCache};
pub use ffi::{
    sd_trust_kit_free_string, sd_trust_kit_verify_pdf_including_revocation_with_options_json,
    sd_trust_kit_verify_pdf_json, sd_trust_kit_verify_pdf_with_options_json,
};
pub use options::{TimedTrustAnchorSet, VerificationOptions};
pub use report::{
    CertificateDetails, PadesLevel, PreservationAssessment, PreservationLevel, SignatureReport,
    StandardsValidationResult, Status, Step, StepKind, TimestampDetails, ValidationIndication,
    ValidationReport, ValidationSubIndication, Verdict,
};
pub use revocation::{CrlCache, CrlCacheEntry, RevocationOptions, RevocationStatus};

use cms::Cms;
use pdf::SigDict;
use report::{aggregate_report, verdict_for};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn verify_pdf(pdf: &[u8]) -> ValidationReport {
    verify_pdf_with_options(pdf, &VerificationOptions::default())
}

pub fn verify_pdf_with_options(pdf: &[u8], options: &VerificationOptions) -> ValidationReport {
    if !pdf::looks_like_pdf_document(pdf) {
        return ValidationReport::new(
            vec![Step::new(
                StepKind::ParsePDF,
                Status::Fail,
                "Document format not recognized as PDF",
            )],
            None,
            vec![],
            None,
            Verdict::Error,
        );
    }

    let (sigs, ignored_bad_cms_count) = usable_signature_dictionaries(pdf);
    if sigs.is_empty() {
        let looks_altered = SigDict::contains_unparseable_signature_contents(pdf);
        if pdf::requires_non_empty_open_password(pdf) {
            return ValidationReport::new(
                vec![Step::new(
                    StepKind::ParsePDF,
                    Status::Fail,
                    "Encrypted PDF cannot be inspected without a password",
                )],
                None,
                vec![],
                None,
                Verdict::Error,
            );
        }
        if !looks_altered && pdf::looks_like_pdf_document(pdf) {
            if !pdf::has_encryption_dictionary(pdf) && !pdf::has_minimal_page_tree(pdf) {
                return ValidationReport::new(
                    vec![Step::new(
                        StepKind::ParsePDF,
                        Status::Fail,
                        "PDF page tree is missing or malformed",
                    )],
                    None,
                    vec![],
                    None,
                    Verdict::Error,
                );
            }
            return ValidationReport::new(
                vec![Step::new(
                    StepKind::ParsePDF,
                    Status::Ok,
                    if ignored_bad_cms_count > 0 {
                        "PDF parsed; no usable signature dictionaries found"
                    } else {
                        "PDF parsed; no signature dictionaries found"
                    },
                )],
                None,
                vec![],
                None,
                Verdict::NoSignatures,
            );
        }
        let kind = if looks_altered {
            StepKind::DocumentModifiedAfterSigning
        } else {
            StepKind::ParsePDF
        };
        let detail = if looks_altered {
            "Document was modified after being signed"
        } else {
            "No /Sig /Contents found"
        };
        return ValidationReport::new(
            vec![Step::new(kind, Status::Fail, detail)],
            None,
            vec![],
            None,
            Verdict::Invalid,
        );
    }

    let visible_total = sigs
        .iter()
        .filter(|sig| !sig.is_document_timestamp())
        .count();
    let mut visible_index = 0usize;
    let mut all_reports = Vec::with_capacity(sigs.len());

    for (offset, sig) in sigs.iter().enumerate() {
        let index = if sig.is_document_timestamp() {
            offset + 1
        } else {
            visible_index += 1;
            visible_index
        };
        let total = if sig.is_document_timestamp() {
            sigs.len()
        } else {
            visible_total
        };
        all_reports.push(verify_signature(
            pdf,
            sig,
            index,
            total,
            offset == sigs.len() - 1,
            sigs.iter()
                .any(|later| later.signed_revision_size() > sig.signed_revision_size()),
            options,
        ));
    }

    let mut signatures = Vec::new();
    let mut document_timestamps = Vec::new();
    for (sig, report) in sigs.iter().zip(all_reports.iter().cloned()) {
        if sig.is_document_timestamp() {
            document_timestamps.push(report);
        } else {
            signatures.push(report);
        }
    }

    if signatures.is_empty() {
        let steps = vec![Step::new(
            StepKind::ParsePDF,
            Status::Ok,
            "PDF parsed; no document signature dictionaries found",
        )];
        let standards = report::standards_result_for(&steps);
        return ValidationReport {
            steps,
            signer_name: None,
            signer_names: vec![],
            signing_time: None,
            verdict: Verdict::NoSignatures,
            signatures,
            document_timestamps,
            standards,
            pades_level: PadesLevel::Unknown,
            preservation: PreservationAssessment::unknown(
                "No PAdES document signature was assessed",
            ),
        };
    }

    let mut signer_names = Vec::new();
    for report in &signatures {
        if let Some(name) = report
            .signer_name
            .as_ref()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
        {
            if !signer_names.iter().any(|seen| seen == name) {
                signer_names.push(name.to_owned());
            }
        }
    }

    aggregate_report(signatures, document_timestamps, all_reports, signer_names)
}

fn usable_signature_dictionaries(pdf: &[u8]) -> (Vec<SigDict>, usize) {
    let parsed = SigDict::parse_all(pdf);
    let mut ignored_bad_cms_count = 0usize;
    let has_field_resolved_signature = parsed
        .iter()
        .any(|sig| pdf::signature_dictionary_has_field_reference(pdf, sig));
    let candidate_count_before_orphan_filter = parsed
        .iter()
        .filter(|sig| {
            !sig.is_usage_rights_signature()
                && !pdf::signature_field_tree_has_self_reference(pdf, sig)
                && !is_bad_encoded_cms_signature(sig)
        })
        .count();
    let sigs = parsed
        .into_iter()
        .filter(|sig| {
            if sig.is_usage_rights_signature()
                || pdf::signature_field_tree_has_self_reference(pdf, sig)
                || (has_field_resolved_signature
                    && candidate_count_before_orphan_filter > 1
                    && pdf::signature_dictionary_is_unreferenced_orphan(pdf, sig))
            {
                false
            } else if is_bad_encoded_cms_signature(sig) {
                ignored_bad_cms_count += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (sigs, ignored_bad_cms_count)
}

fn is_bad_encoded_cms_signature(sig: &SigDict) -> bool {
    let Some(cms) = Cms::parse(&sig.cms_bytes) else {
        return false;
    };
    let [signer] = cms.signer_infos.as_slice() else {
        return false;
    };
    let Some(signer_cert_der) = cms.cert_for_signer(signer) else {
        return false;
    };
    if signer.signature_alg_oid == crypto::OID_ECDSA_SHA1 {
        return true;
    }
    !crypto::signature_algorithm_matches_certificate_key(
        &signer.signature_alg_oid,
        &signer_cert_der,
    )
}

pub fn verify_pdf_including_revocation_with_options(
    pdf: &[u8],
    verification_options: &VerificationOptions,
    revocation_options: &RevocationOptions,
) -> ValidationReport {
    let (sigs, _) = usable_signature_dictionaries(pdf);
    let report = verify_pdf_with_options(pdf, verification_options);
    if sigs.is_empty() || report.signatures.is_empty() {
        return report;
    }

    let mut signatures = report.signatures;
    for (signature_index, sig) in sigs
        .iter()
        .filter(|sig| !sig.is_document_timestamp())
        .enumerate()
    {
        let Some(signature_report) = signatures.get_mut(signature_index) else {
            break;
        };
        append_revocation_step(signature_report, sig, revocation_options);
    }

    let mut all_reports = signatures.clone();
    all_reports.extend(report.document_timestamps.clone());
    aggregate_report(
        signatures,
        report.document_timestamps,
        all_reports,
        report.signer_names,
    )
}

fn verify_signature(
    pdf: &[u8],
    sig: &SigDict,
    index: usize,
    total: usize,
    require_full_coverage: bool,
    has_later_signature_revision: bool,
    options: &VerificationOptions,
) -> SignatureReport {
    let mut steps = Vec::new();
    let mut signing_time = None;
    let certificate_chain;
    let mut timestamp_details = None;
    let signed_revision_size = sig.signed_revision_size();
    let is_pades_baseline = is_pades_baseline_signature(sig);

    steps.push(Step::new(
        StepKind::ParsePDF,
        Status::Ok,
        format!(
            "Signature {} of {}, /ByteRange {:?}, CMS {} bytes",
            index,
            total,
            sig.byte_range,
            sig.cms_bytes.len()
        ),
    ));

    let make_report = |steps: Vec<Step>,
                       signer_name: Option<String>,
                       signing_time: Option<String>,
                       signer_certificate: Option<CertificateDetails>,
                       certificate_chain: Vec<CertificateDetails>,
                       timestamp_details: Option<TimestampDetails>,
                       verdict: Verdict| {
        let pades_level = report::pades_level_for_signature_steps(&steps, is_pades_baseline);
        let preservation = report::preservation_assessment_for_level(pades_level);
        SignatureReport {
            index,
            total,
            signed_revision_size,
            current_file_size: pdf.len(),
            byte_range: sig.byte_range.clone(),
            steps,
            signer_name,
            signing_time,
            signer_certificate,
            certificate_chain,
            timestamp_details,
            verdict,
            pades_level,
            preservation,
        }
    };

    let coverage_ok = sig.byte_range.len() == 4
        && sig.byte_range[0] == 0
        && sig.byte_range_gap_matches_contents()
        && signed_revision_size <= pdf.len();
    let has_later_validation_data_object_change;
    if coverage_ok {
        let has_later_revision = signed_revision_size < pdf.len();
        has_later_validation_data_object_change = !sig.is_document_timestamp()
            && has_later_revision
            && !has_later_signature_revision
            && pdf::later_validation_data_revision_changes_existing_object(
                pdf,
                signed_revision_size,
            );
        let has_only_trailing_whitespace =
            has_later_revision && pdf::trailing_bytes_are_pdf_whitespace(pdf, signed_revision_size);
        let has_only_later_validation_data = has_later_revision
            && !has_later_validation_data_object_change
            && pdf::later_revision_looks_like_validation_data_only(pdf, signed_revision_size);
        let detail = if has_later_revision {
            if has_only_trailing_whitespace {
                "Covers entire file except trailing whitespace".to_owned()
            } else if has_only_later_validation_data {
                "Covers signed revision; later revision adds validation data".to_owned()
            } else {
                format!(
                    "Covers signed revision ({} B of current {} B)",
                    report::format_int_dot(signed_revision_size),
                    report::format_int_dot(pdf.len())
                )
            }
        } else {
            format!(
                "Covers entire file ({} B)",
                report::format_int_dot(pdf.len())
            )
        };
        let status = if require_full_coverage
            && has_later_revision
            && !has_only_trailing_whitespace
            && !has_only_later_validation_data
        {
            Status::Warn
        } else {
            Status::Ok
        };
        steps.push(Step::new(StepKind::ByteRangeCoverage, status, detail));
    } else {
        steps.push(Step::new(
            StepKind::ByteRangeCoverage,
            Status::Fail,
            format!(
                "file={} vs signedRevision={}",
                report::format_int_dot(pdf.len()),
                report::format_int_dot(signed_revision_size)
            ),
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    }
    if pdf::signature_dictionary_changed_after_signed_revision(pdf, sig) {
        steps.push(Step::new(
            StepKind::DocumentModifiedAfterSigning,
            Status::Fail,
            "Signature dictionary changed after the signed revision",
        ));
    }
    if pdf::signature_has_shadow_copy_after_signed_revision(pdf, sig) {
        steps.push(Step::new(
            StepKind::DocumentModifiedAfterSigning,
            Status::Fail,
            "A later PDF revision adds a duplicate signature dictionary for the same signed data",
        ));
    }
    if pdf::signature_field_reference_changed_after_signed_revision(pdf, sig) {
        steps.push(Step::new(
            StepKind::DocumentModifiedAfterSigning,
            Status::Fail,
            "Signature field reference changed after the signed revision",
        ));
    }
    if pdf::page_count_changed_after_signed_revision(pdf, sig) {
        steps.push(Step::new(
            StepKind::DocumentModifiedAfterSigning,
            Status::Fail,
            "The number of pages changed after the signed revision",
        ));
    }
    if pdf::signature_has_duplicate_field_references_in_signed_revision(pdf, sig) {
        steps.push(Step::new(
            StepKind::SignatureFieldResolution,
            Status::Fail,
            "Multiple signature fields reference the same signature dictionary",
        ));
    }
    if has_later_validation_data_object_change {
        steps.push(Step::new(
            StepKind::DocumentModifiedAfterSigning,
            Status::Fail,
            "Later validation-data revision changed an existing PDF object",
        ));
    }
    let has_byte_range_coverage_warning = steps
        .iter()
        .any(|step| step.kind == StepKind::ByteRangeCoverage && step.status == Status::Warn);

    let Some((range1, range2)) = pdf::validated_byte_range(&sig.byte_range, pdf.len()) else {
        steps.push(Step::new(
            StepKind::ByteRangeBounds,
            Status::Fail,
            "Range points outside the PDF",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    };
    let mut signed_data = Vec::with_capacity(range1.len() + range2.len());
    signed_data.extend_from_slice(&pdf[range1]);
    signed_data.extend_from_slice(&pdf[range2]);

    if sig.is_document_timestamp() {
        return timestamp::verify_document_timestamp(
            sig,
            &signed_data,
            steps,
            make_report,
            options,
        );
    }

    let Some(cms) = Cms::parse(&sig.cms_bytes) else {
        steps.push(Step::new(
            StepKind::CmsStructure,
            Status::Fail,
            "Could not parse SignedData",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    };
    steps.push(Step::new(
        StepKind::CmsStructure,
        Status::Ok,
        format!(
            "version={}, certs={}, signerInfos={}, digestAlg={}",
            cms.version,
            cms.certificates.len(),
            cms.signer_infos.len(),
            cms.digest_alg_oid
        ),
    ));

    if cms.e_content.as_deref() == Some(&[]) {
        steps.push(Step::new(
            StepKind::SignatureVerifySignedAttributes,
            Status::Fail,
            "CMS encapsulated eContent is empty",
        ));
    }
    if signature_policy_uses_signature_algorithm_as_digest(&cms) {
        steps.push(Step::new(
            StepKind::ParsePDF,
            Status::Fail,
            "Unsupported signature-policy digest algorithm",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Error);
    }
    if cms_has_malformed_ocsp_archive_cutoff(&sig.cms_bytes) {
        steps.push(Step::new(
            StepKind::ParsePDF,
            Status::Fail,
            "Malformed OCSP archiveCutOff extension",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Error);
    }

    if !has_byte_range_coverage_warning && is_pades_baseline && cms.signer_infos.len() > 1 {
        steps.push(Step::new(
            StepKind::PadesBaselineRequirements,
            Status::Fail,
            format!(
                "SignedData.signerInfos must contain exactly one signerInfo, found {}",
                cms.signer_infos.len()
            ),
        ));
    }
    if !has_byte_range_coverage_warning && is_pades_baseline && cms.e_content.is_some() {
        steps.push(Step::new(
            StepKind::PadesBaselineRequirements,
            Status::Fail,
            "PAdES signatures must use detached CMS content; encapsulated eContent is present",
        ));
    }
    if !has_byte_range_coverage_warning
        && is_pades_baseline
        && cms.e_content_type_oid != cms::OID_DATA
    {
        steps.push(Step::new(
            StepKind::PadesBaselineRequirements,
            Status::Fail,
            format!(
                "SignedData encapContentInfo eContentType is {}, expected id-data",
                cms.e_content_type_oid
            ),
        ));
    }

    let Some(signer) = cms.signer_infos.first() else {
        steps.push(Step::new(
            StepKind::SignerInfoPresent,
            Status::Fail,
            "No signerInfos",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    };

    if !has_byte_range_coverage_warning && is_pades_baseline {
        if let Some(error) = pades_signed_attribute_baseline_error(signer) {
            steps.push(Step::new(
                StepKind::PadesBaselineRequirements,
                Status::Fail,
                error,
            ));
        }
    }

    let Some(pdf_digest) = crypto::digest(&signed_data, &signer.digest_alg_oid) else {
        steps.push(Step::new(
            StepKind::MessageDigestMatches,
            Status::Fail,
            format!("unsupported digest algorithm {}", signer.digest_alg_oid),
        ));
        let verdict = if sig.sub_filter.as_deref() == Some("adbe.pkcs7.sha1")
            && signer.digest_alg_oid == crypto::OID_RSA_SHA1
        {
            Verdict::Inconclusive
        } else {
            Verdict::Invalid
        };
        return make_report(steps, None, None, None, vec![], None, verdict);
    };
    if signer.signed_attrs_raw_bytes.is_empty() {
        steps.push(Step::new(
            StepKind::MessageDigestAttribute,
            Status::Skip,
            "no signed attributes",
        ));
    } else {
        let md_attr = signer
            .find_signed_attribute(cms::OID_MESSAGE_DIGEST)
            .and_then(asn1::first_octet_string);
        let Some(md_value) = md_attr else {
            steps.push(Step::new(
                StepKind::MessageDigestAttribute,
                Status::Fail,
                "missing",
            ));
            return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
        };
        if md_value == pdf_digest {
            steps.push(Step::new(
                StepKind::MessageDigestMatches,
                Status::Ok,
                format!(
                    "{} = {}\u{2026}",
                    crypto::digest_name(&signer.digest_alg_oid),
                    hex::encode(&md_value[..md_value.len().min(8)])
                ),
            ));
        } else {
            steps.push(Step::new(
                StepKind::MessageDigestMatches,
                Status::Fail,
                format!(
                    "expected={}\u{2026} got={}\u{2026}",
                    hex::encode(&pdf_digest[..pdf_digest.len().min(6)]),
                    hex::encode(&md_value[..md_value.len().min(6)])
                ),
            ));
            return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
        }
    }

    let Some(signer_cert_der) = cms.cert_for_signer(signer) else {
        steps.push(Step::new(
            StepKind::SignerCertificatePresent,
            Status::Fail,
            "CMS contains no certificate matching the signer identifier",
        ));
        let verdict = verdict_for(&steps);
        return make_report(steps, None, None, None, vec![], None, verdict);
    };

    let signer_name = trust::certificate_common_name(&signer_cert_der);
    let signer_certificate = trust::certificate_details(&signer_cert_der);
    if let Some(st_attr) = signer.find_signed_attribute(cms::OID_SIGNING_TIME) {
        signing_time = asn1::first_time_string(st_attr);
    } else if let Some(date) = sig.modification_date.clone() {
        signing_time = Some(date);
    }
    let claimed_signing_time = signing_time
        .as_deref()
        .and_then(revocation::claimed_time_to_unix_seconds);
    let signature_timestamp_attr = signer.find_unsigned_attribute(cms::OID_TIME_STAMP_TOKEN);

    let mut signature_input = signed_data.clone();
    if !signer.signed_attrs_raw_bytes.is_empty() {
        signature_input = signer.signed_attrs_raw_bytes.clone();
        signature_input[0] = 0x31;
    }
    let signature_step_kind = if signer.signed_attrs_raw_bytes.is_empty() {
        StepKind::SignatureVerifyContent
    } else {
        StepKind::SignatureVerifySignedAttributes
    };
    let sig_ok = crypto::verify_any_cms_signature(
        &signature_input,
        &signer.signature_alg_oid,
        signer.signature_alg_params.as_deref(),
        &signer.digest_alg_oid,
        &signer.signature,
        &signer_cert_der,
    );
    if sig_ok {
        steps.push(Step::new(
            signature_step_kind,
            Status::Ok,
            format!(
                "sigAlg={} digest={}",
                signer.signature_alg_oid, signer.digest_alg_oid
            ),
        ));
    } else {
        steps.push(Step::new(
            signature_step_kind,
            Status::Fail,
            if signer.signed_attrs_raw_bytes.is_empty() {
                "signature does not match content"
            } else {
                "signature does not match SignedAttrs"
            },
        ));
    }

    if !has_byte_range_coverage_warning && is_pades_baseline {
        if let Some(error) = signing_certificate_attribute_error(signer, &signer_cert_der) {
            steps.push(Step::new(
                StepKind::PadesBaselineRequirements,
                Status::Fail,
                error,
            ));
        }
    }

    let intermediates: Vec<Vec<u8>> = cms
        .certificates
        .iter()
        .filter(|cert| **cert != signer_cert_der)
        .cloned()
        .collect();
    let signer_trust_anchors = trust_anchors_for_time(
        &options.signer_trust_anchors,
        &options.signer_trust_anchor_sets,
        claimed_signing_time,
    );
    let trusted_chain = if !options.signer_trust_anchor_sets.is_empty() {
        let preferred_signer_trust_anchors =
            trust_anchors_for_time(&[], &options.signer_trust_anchor_sets, claimed_signing_time);
        trust::trusted_chain_to_anchor_with_preferred_anchors_at_time(
            &signer_cert_der,
            &intermediates,
            &signer_trust_anchors,
            &preferred_signer_trust_anchors,
            claimed_signing_time,
        )
    } else {
        trust::trusted_chain_to_anchor_at_time(
            &signer_cert_der,
            &intermediates,
            &signer_trust_anchors,
            claimed_signing_time,
        )
    };
    let signer_chain_trusted = trusted_chain.is_some();
    if let Some(chain) = trusted_chain {
        steps.push(Step::new(
            StepKind::SignerCertificateChain,
            Status::Ok,
            "-> configured signer trust anchor",
        ));
        certificate_chain = chain
            .iter()
            .filter_map(|cert| trust::certificate_details(cert))
            .collect();
    } else {
        steps.push(Step::new(
            StepKind::SignerCertificateChain,
            Status::Warn,
            "signer certificate is not trusted by configured trust anchors",
        ));
        let mut chain = vec![signer_cert_der.clone()];
        chain.extend(intermediates);
        certificate_chain = trust::unique_certificates(chain)
            .iter()
            .filter_map(|cert| trust::certificate_details(cert))
            .collect();
    }

    if signer_chain_trusted && !has_byte_range_coverage_warning {
        match trust::cert_allows_document_signing_key_usage(&signer_cert_der) {
            Some(true) => steps.push(Step::new(
                StepKind::SignerCertificateKeyUsage,
                Status::Ok,
                "digitalSignature or nonRepudiation/contentCommitment allowed",
            )),
            Some(false) => steps.push(Step::new(
                StepKind::SignerCertificateKeyUsage,
                Status::Fail,
                "keyUsage does not allow document signing",
            )),
            None => steps.push(Step::new(
                StepKind::SignerCertificateKeyUsage,
                Status::Warn,
                "could not evaluate keyUsage",
            )),
        }
        match trust::cert_allows_document_signing_extended_key_usage(&signer_cert_der) {
            Some(true) => steps.push(Step::new(
                StepKind::SignerCertificateExtendedKeyUsage,
                Status::Ok,
                "extendedKeyUsage is absent or allows document signing",
            )),
            Some(false) => steps.push(Step::new(
                StepKind::SignerCertificateExtendedKeyUsage,
                Status::Fail,
                "extendedKeyUsage does not allow document signing",
            )),
            None => steps.push(Step::new(
                StepKind::SignerCertificateExtendedKeyUsage,
                Status::Warn,
                "could not evaluate extendedKeyUsage",
            )),
        }
    }

    if let Some(tst_attr) = signature_timestamp_attr {
        timestamp_details =
            timestamp::verify_signature_timestamp(&mut steps, &signer.signature, tst_attr, options);
    } else {
        steps.push(Step::new(
            StepKind::TsaTimestamp,
            Status::Skip,
            "no id-aa-timeStampToken (PAdES-B-B only)",
        ));
    }

    if signer_chain_trusted && !has_byte_range_coverage_warning {
        append_signer_certificate_validity_step(
            &mut steps,
            &signer_cert_der,
            timestamp_details.as_ref(),
        );
    }

    let verdict = verdict_for(&steps);
    make_report(
        steps,
        signer_name,
        signing_time,
        signer_certificate,
        certificate_chain,
        timestamp_details,
        verdict,
    )
}

fn append_signer_certificate_validity_step(
    steps: &mut Vec<Step>,
    signer_cert_der: &[u8],
    timestamp_details: Option<&TimestampDetails>,
) {
    if let Some(timestamp_time) = timestamp_details
        .and_then(|details| details.timestamp_time.as_deref())
        .and_then(revocation::asn1_time_to_unix_seconds)
    {
        match trust::certificate_is_valid_at_unix_time(signer_cert_der, timestamp_time) {
            Some(true) if trusted_signature_timestamp_steps_are_ok(steps) => {
                steps.push(Step::new(
                    StepKind::SignerCertificateValidity,
                    Status::Ok,
                    "valid at trusted timestamp time",
                ));
                return;
            }
            Some(false) => {
                steps.push(Step::new(
                    StepKind::SignerCertificateValidity,
                    Status::Fail,
                    "signer certificate is not valid at timestamp time",
                ));
                return;
            }
            Some(true) => {}
            None => {
                steps.push(Step::new(
                    StepKind::SignerCertificateValidity,
                    Status::Warn,
                    "could not read signer certificate validity period",
                ));
                return;
            }
        }
    }

    let now = current_unix_seconds();
    match trust::certificate_is_valid_at_unix_time(signer_cert_der, now) {
        Some(true) => steps.push(Step::new(
            StepKind::SignerCertificateValidity,
            Status::Ok,
            "valid at validation time",
        )),
        Some(false) => steps.push(Step::new(
            StepKind::SignerCertificateValidity,
            Status::Fail,
            "signer certificate is not valid at validation time and no trusted proof-of-existence is present",
        )),
        None => steps.push(Step::new(
            StepKind::SignerCertificateValidity,
            Status::Warn,
            "could not read signer certificate validity period",
        )),
    }
}

fn trusted_signature_timestamp_steps_are_ok(steps: &[Step]) -> bool {
    step_ok(steps, StepKind::TsaMessageImprint)
        && step_ok(steps, StepKind::TsaSignatureVerify)
        && step_ok(steps, StepKind::TsaExtendedKeyUsage)
        && step_ok(steps, StepKind::TsaCertificateChain)
}

fn step_ok(steps: &[Step], kind: StepKind) -> bool {
    steps
        .iter()
        .any(|step| step.kind == kind && step.status == Status::Ok)
}

fn current_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn is_pades_baseline_signature(sig: &SigDict) -> bool {
    sig.sub_filter.as_deref() == Some("ETSI.CAdES.detached")
}

fn signature_policy_uses_signature_algorithm_as_digest(cms: &Cms) -> bool {
    const OID_SIGNATURE_POLICY_ID: &str = "1.2.840.113549.1.9.16.2.15";
    cms.signer_infos.iter().any(|signer| {
        signer
            .find_signed_attribute(OID_SIGNATURE_POLICY_ID)
            .is_some_and(|attr| {
                contains_der_oid(attr, crypto::OID_RSA_SHA1)
                    || contains_der_oid(attr, crypto::OID_RSA_SHA256)
                    || contains_der_oid(attr, crypto::OID_RSA_SHA384)
                    || contains_der_oid(attr, crypto::OID_RSA_SHA512)
            })
    })
}

fn cms_has_malformed_ocsp_archive_cutoff(cms_der: &[u8]) -> bool {
    const OID_OCSP_ARCHIVE_CUTOFF_DER: &[u8] = &[
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06,
    ];
    cms_der
        .windows(OID_OCSP_ARCHIVE_CUTOFF_DER.len())
        .position(|window| window == OID_OCSP_ARCHIVE_CUTOFF_DER)
        .is_some_and(|pos| {
            let scan = &cms_der[pos + OID_OCSP_ARCHIVE_CUTOFF_DER.len()..];
            scan.windows(3)
                .take(64)
                .any(|window| window[0] == 0x18 && window[1] > 0 && window[2] == b'-')
        })
}

fn contains_der_oid(der: &[u8], oid: &str) -> bool {
    let Some(content) = der_oid_content(oid) else {
        return false;
    };
    let mut encoded = vec![0x06];
    encoded.extend(asn1::der_length(content.len()));
    encoded.extend(content);
    der.windows(encoded.len()).any(|window| window == encoded)
}

fn der_oid_content(oid: &str) -> Option<Vec<u8>> {
    let parts: Vec<u32> = oid
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.len() < 2 {
        return None;
    }
    let mut out = vec![(parts[0] * 40 + parts[1]) as u8];
    for part in parts.into_iter().skip(2) {
        let mut stack = vec![(part & 0x7f) as u8];
        let mut value = part >> 7;
        while value > 0 {
            stack.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        out.extend(stack.into_iter().rev());
    }
    Some(out)
}

fn pades_signed_attribute_baseline_error(signer: &cms::SignerInfo) -> Option<String> {
    if signer.signed_attrs_raw_bytes.is_empty() {
        return Some("PAdES Baseline requires signed attributes".to_owned());
    }

    let content_type_count = signer.count_signed_attribute("1.2.840.113549.1.9.3");
    if content_type_count != 1 {
        return Some(format!(
            "content-type signed attribute must be present exactly once, found {content_type_count}"
        ));
    }
    let content_type_attr = signer.find_signed_attribute("1.2.840.113549.1.9.3")?;
    if attribute_value_count(content_type_attr) != 1 {
        return Some("content-type signed attribute must contain exactly one value".to_owned());
    }
    if first_oid_in_attribute_values(content_type_attr).as_deref() != Some(cms::OID_DATA) {
        return Some("content-type signed attribute must be id-data".to_owned());
    }

    let message_digest_count = signer.count_signed_attribute(cms::OID_MESSAGE_DIGEST);
    if message_digest_count != 1 {
        return Some(format!(
            "message-digest signed attribute must be present exactly once, found {message_digest_count}"
        ));
    }
    let message_digest_attr = signer.find_signed_attribute(cms::OID_MESSAGE_DIGEST)?;
    if attribute_value_count(message_digest_attr) != 1 {
        return Some("message-digest signed attribute must contain exactly one value".to_owned());
    }

    None
}

fn signing_certificate_attribute_error(
    signer: &cms::SignerInfo,
    signer_cert_der: &[u8],
) -> Option<String> {
    let signing_cert_v1_count = signer.count_signed_attribute(cms::OID_SIGNING_CERTIFICATE);
    let signing_cert_v2_count = signer.count_signed_attribute(cms::OID_SIGNING_CERTIFICATE_V2);
    let total = signing_cert_v1_count + signing_cert_v2_count;
    if total != 1 {
        return Some(format!(
            "signing-certificate or signing-certificate-v2 must be present exactly once, found {total}"
        ));
    }

    let signer_digest_oid = crypto::normalized_digest_oid(&signer.digest_alg_oid);
    if signing_cert_v1_count == 1 && signer_digest_oid != crypto::OID_SHA1 {
        return Some(
            "signing-certificate v1 may only be used with SHA-1 signatures; use signing-certificate-v2"
                .to_owned(),
        );
    }

    let matches = if signing_cert_v1_count == 1 {
        signer
            .find_signed_attribute(cms::OID_SIGNING_CERTIFICATE)
            .is_some_and(|attr| {
                signing_certificate_v1_hashes(attr).iter().any(|hash| {
                    crypto::digest(signer_cert_der, crypto::OID_SHA1).as_ref() == Some(hash)
                })
            })
    } else {
        signer
            .find_signed_attribute(cms::OID_SIGNING_CERTIFICATE_V2)
            .is_some_and(|attr| {
                signing_certificate_v2_hashes(attr)
                    .iter()
                    .any(|(digest_oid, hash)| {
                        crypto::digest(signer_cert_der, digest_oid).as_ref() == Some(hash)
                    })
            })
    };

    if !matches {
        return Some(
            "signing-certificate attribute does not contain a hash of the signer certificate"
                .to_owned(),
        );
    }

    None
}

fn attribute_value_count(attribute_values_der: &[u8]) -> usize {
    let mut reader = asn1::Reader::new(attribute_values_der);
    let mut count = 0usize;
    while reader.read_tlv().is_some() {
        count += 1;
    }
    count
}

fn first_oid_in_attribute_values(attribute_values_der: &[u8]) -> Option<String> {
    let mut reader = asn1::Reader::new(attribute_values_der);
    while let Some(value) = reader.read_tlv() {
        if value.tag == 0x06 {
            return Some(asn1::oid_string(&value.content));
        }
    }
    None
}

fn signing_certificate_v1_hashes(attribute_values_der: &[u8]) -> Vec<Vec<u8>> {
    signing_certificate_hashes(attribute_values_der, |ess_cert_id| {
        let mut ess_reader = asn1::Reader::new(ess_cert_id);
        let cert_hash = ess_reader.read_tlv()?;
        (cert_hash.tag == 0x04).then_some(cert_hash.content)
    })
}

fn signing_certificate_v2_hashes(attribute_values_der: &[u8]) -> Vec<(String, Vec<u8>)> {
    signing_certificate_hashes(attribute_values_der, |ess_cert_id| {
        let mut ess_reader = asn1::Reader::new(ess_cert_id);
        let first = ess_reader.read_tlv()?;
        if first.tag == 0x04 {
            return Some((crypto::OID_SHA256.to_owned(), first.content));
        }
        if first.tag != 0x30 {
            return None;
        }
        let digest_oid = cms::algorithm_identifier_oid(&first.content)?;
        let cert_hash = ess_reader.read_tlv()?;
        (cert_hash.tag == 0x04).then_some((digest_oid, cert_hash.content))
    })
}

fn signing_certificate_hashes<T>(
    attribute_values_der: &[u8],
    mut parse_ess_cert_id: impl FnMut(&[u8]) -> Option<T>,
) -> Vec<T> {
    let mut out = Vec::new();
    let mut values = asn1::Reader::new(attribute_values_der);
    while let Some(value) = values.read_tlv() {
        if value.tag != 0x30 {
            continue;
        }
        let mut signing_cert = asn1::Reader::new(&value.content);
        let Some(certs) = signing_cert.read_tlv() else {
            continue;
        };
        if certs.tag != 0x30 {
            continue;
        }
        let mut cert_ids = asn1::Reader::new(&certs.content);
        while let Some(ess_cert_id) = cert_ids.read_tlv() {
            if ess_cert_id.tag == 0x30 {
                if let Some(parsed) = parse_ess_cert_id(&ess_cert_id.content) {
                    out.push(parsed);
                }
            }
        }
    }
    out
}

fn append_revocation_step(
    report: &mut SignatureReport,
    sig: &SigDict,
    options: &RevocationOptions,
) {
    let Some(cms) = Cms::parse(&sig.cms_bytes) else {
        report.steps.push(Step::new(
            StepKind::RevocationSigner,
            Status::Skip,
            "signer certificate unavailable",
        ));
        report.verdict = verdict_for(&report.steps);
        return;
    };
    let Some(signer) = cms.signer_infos.first() else {
        report.steps.push(Step::new(
            StepKind::RevocationSigner,
            Status::Skip,
            "signer certificate unavailable",
        ));
        report.verdict = verdict_for(&report.steps);
        return;
    };
    let Some(signer_cert_der) = cms.cert_for_signer(signer) else {
        report.steps.push(Step::new(
            StepKind::RevocationSigner,
            Status::Skip,
            "signer certificate unavailable",
        ));
        report.verdict = verdict_for(&report.steps);
        return;
    };

    let mut issuer_certificates: Vec<Vec<u8>> = cms
        .certificates
        .iter()
        .filter(|cert| **cert != signer_cert_der)
        .cloned()
        .collect();
    issuer_certificates.extend(
        report
            .certificate_chain
            .iter()
            .map(|cert| cert.der.clone())
            .filter(|cert| *cert != signer_cert_der),
    );
    issuer_certificates = trust::unique_certificates(issuer_certificates);

    let validation_time = signature_revocation_time_unix_seconds(report, options.now_unix_seconds);
    let status = revocation::check_certificate_status(
        &signer_cert_der,
        &issuer_certificates,
        validation_time,
        &options.crl_cache,
    );
    match status {
        RevocationStatus::Good => report.steps.push(Step::new(
            StepKind::RevocationSigner,
            Status::Ok,
            "certificate is not listed in the current CRL",
        )),
        RevocationStatus::Unavailable(error) => {
            report
                .steps
                .push(Step::new(StepKind::RevocationSigner, Status::Warn, error))
        }
        RevocationStatus::Revoked { revoked_at } => {
            if let Some(revoked_at) = revoked_at {
                if validation_time < revoked_at {
                    report.steps.push(Step::new(
                        StepKind::RevocationSigner,
                        Status::Warn,
                        "certificate was revoked after the signing time",
                    ));
                } else {
                    report.steps.push(Step::new(
                        StepKind::RevocationSigner,
                        Status::Fail,
                        "certificate was revoked before the signing time",
                    ));
                }
            } else {
                report.steps.push(Step::new(
                    StepKind::RevocationSigner,
                    Status::Fail,
                    "certificate is listed as revoked; CRL did not include a revocation date",
                ));
            }
        }
    }
    report.verdict = verdict_for(&report.steps);
    report.refresh_preservation();
}

fn signature_revocation_time_unix_seconds(report: &SignatureReport, now_unix_seconds: f64) -> f64 {
    let has_trusted_timestamp =
        report
            .steps
            .iter()
            .any(|step| step.kind == StepKind::TsaMessageImprint && step.status == Status::Ok)
            && report
                .steps
                .iter()
                .any(|step| step.kind == StepKind::TsaSignatureVerify && step.status == Status::Ok)
            && report.steps.iter().any(|step| {
                step.kind == StepKind::TsaExtendedKeyUsage && step.status == Status::Ok
            })
            && report.steps.iter().any(|step| {
                step.kind == StepKind::TsaCertificateChain && step.status == Status::Ok
            });

    if has_trusted_timestamp {
        if let Some(timestamp_time) = report
            .timestamp_details
            .as_ref()
            .and_then(|details| details.timestamp_time.as_deref())
        {
            if let Some(time) = revocation::asn1_time_to_unix_seconds(timestamp_time) {
                return time;
            }
        }
    }

    now_unix_seconds
}

fn trust_anchors_for_time(
    default_anchors: &[Vec<u8>],
    timed_anchor_sets: &[TimedTrustAnchorSet],
    validation_time: Option<f64>,
) -> Vec<Vec<u8>> {
    let mut anchors = default_anchors.to_vec();
    if let Some(validation_time) = validation_time {
        for set in timed_anchor_sets {
            if set
                .valid_from_unix_seconds
                .is_some_and(|valid_from| validation_time < valid_from)
            {
                continue;
            }
            if set
                .valid_until_unix_seconds
                .is_some_and(|valid_until| validation_time >= valid_until)
            {
                continue;
            }
            anchors.extend(set.anchors.iter().cloned());
        }
    }
    trust::unique_certificates(anchors)
}

pub fn report_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_time_ignores_untrusted_claimed_signing_time() {
        let report = test_signature_report(vec![], Some("D:20100101000000Z".to_owned()), None);

        assert_eq!(
            signature_revocation_time_unix_seconds(&report, 1_779_530_582.0),
            1_779_530_582.0
        );
    }

    #[test]
    fn revocation_time_uses_trusted_signature_timestamp() {
        let report = test_signature_report(
            vec![
                Step::new(StepKind::TsaMessageImprint, Status::Ok, "ok"),
                Step::new(StepKind::TsaSignatureVerify, Status::Ok, "ok"),
                Step::new(StepKind::TsaExtendedKeyUsage, Status::Ok, "ok"),
                Step::new(StepKind::TsaCertificateChain, Status::Ok, "ok"),
            ],
            Some("D:20100101000000Z".to_owned()),
            Some("260525000000Z".to_owned()),
        );

        assert_eq!(
            signature_revocation_time_unix_seconds(&report, 1_779_530_582.0),
            1_779_667_200.0
        );
    }

    #[test]
    fn signature_selection_ignores_in_file_orphan_signature_dictionary() {
        let pdf = br#"%PDF-1.7
1 0 obj
<< /Type /Catalog /AcroForm 2 0 R >>
endobj
2 0 obj
<< /Fields [3 0 R] >>
endobj
3 0 obj
<< /FT /Sig /V 8 0 R >>
endobj
8 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached
   /ByteRange [0 0 0 0] /Contents <3000> >>
endobj
9 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached
   /ByteRange [0 1 2 3] /Contents <3000> >>
endobj
%%EOF"#;

        let (sigs, ignored_bad_cms_count) = usable_signature_dictionaries(pdf);

        assert_eq!(ignored_bad_cms_count, 0);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].object_number, Some(8));
    }

    fn test_signature_report(
        steps: Vec<Step>,
        signing_time: Option<String>,
        timestamp_time: Option<String>,
    ) -> SignatureReport {
        SignatureReport {
            index: 1,
            total: 1,
            signed_revision_size: 0,
            current_file_size: 0,
            byte_range: vec![],
            steps,
            signer_name: None,
            signing_time,
            signer_certificate: None,
            certificate_chain: vec![],
            timestamp_details: timestamp_time.map(|timestamp_time| TimestampDetails {
                timestamp_time: Some(timestamp_time),
                policy_oid: None,
                serial_number_hex: None,
                message_imprint_algorithm: None,
                message_imprint_hash: None,
                tsa_certificate: None,
                tsa_certificate_chain: vec![],
                trust_detail: None,
            }),
            verdict: Verdict::Inconclusive,
            pades_level: PadesLevel::BaselineB,
            preservation: PreservationAssessment::unknown("test report"),
        }
    }
}
