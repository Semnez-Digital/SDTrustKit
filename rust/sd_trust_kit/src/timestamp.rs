use crate::cms::Cms;
use crate::report::{
    CertificateDetails, SignatureReport, Status, Step, StepKind, TimestampDetails, Verdict,
};
use crate::VerificationOptions;
use crate::{asn1, crypto, trust};

#[derive(Clone, Debug)]
struct TstInfoDetails {
    policy_oid: Option<String>,
    message_imprint_algorithm_oid: String,
    message_imprint_hash: Vec<u8>,
    serial_number_hex: Option<String>,
    gen_time: Option<String>,
}

pub fn verify_signature_timestamp(
    steps: &mut Vec<Step>,
    signer_signature: &[u8],
    tst_attr: &[u8],
    options: &VerificationOptions,
) -> Option<TimestampDetails> {
    let require_timestamp_trust = has_configured_timestamp_trust(options);
    let Some(tst_cms) = Cms::parse(tst_attr) else {
        steps.push(Step::new(
            StepKind::TsaTimestamp,
            Status::Fail,
            "id-aa-timeStampToken present but CMS could not be parsed",
        ));
        return None;
    };
    let Some(tst_signer) = tst_cms.signer_infos.first() else {
        steps.push(Step::new(
            StepKind::TsaTimestamp,
            Status::Fail,
            "id-aa-timeStampToken present but has no signerInfos",
        ));
        return None;
    };
    if tst_cms.e_content_type_oid != crate::cms::OID_TST_INFO {
        steps.push(Step::new(
            StepKind::TsaTimestamp,
            Status::Fail,
            format!(
                "TimeStampToken eContentType is {}, expected {}",
                tst_cms.e_content_type_oid,
                crate::cms::OID_TST_INFO
            ),
        ));
        return None;
    }

    let tst_info = tst_cms
        .e_content
        .as_deref()
        .and_then(parse_tst_info_details);
    let mut imprint_ok = false;
    let mut imprint_detail = "no TSTInfo eContent".to_owned();
    if let Some(details) = &tst_info {
        let computed = crypto::digest(signer_signature, &details.message_imprint_algorithm_oid);
        imprint_ok = computed.as_deref() == Some(details.message_imprint_hash.as_slice());
        imprint_detail = format!(
            "hash={} over signer.signature {}B",
            details.message_imprint_algorithm_oid,
            signer_signature.len()
        );
    }
    steps.push(Step::new(
        StepKind::TsaMessageImprint,
        if imprint_ok { Status::Ok } else { Status::Fail },
        imprint_detail,
    ));

    let tsa_signer_cert = tst_cms
        .cert_for_signer(tst_signer)
        .or_else(|| tst_cms.certificates.last().cloned());
    let tsa_digest_alg = if tst_signer.digest_alg_oid.is_empty() {
        &tst_cms.digest_alg_oid
    } else {
        &tst_signer.digest_alg_oid
    };
    let tsa_sig_ok = if let Some(cert) = &tsa_signer_cert {
        let mut tsa_input = tst_signer.signed_attrs_raw_bytes.clone();
        if !tsa_input.is_empty() {
            tsa_input[0] = 0x31;
        }
        crypto::verify_any_cms_signature(
            &tsa_input,
            &tst_signer.signature_alg_oid,
            tst_signer.signature_alg_params.as_deref(),
            tsa_digest_alg,
            &tst_signer.signature,
            cert,
        )
    } else {
        false
    };
    steps.push(Step::new(
        StepKind::TsaSignatureVerify,
        if tsa_sig_ok { Status::Ok } else { Status::Fail },
        format!(
            "sigAlg={} digest={}",
            tst_signer.signature_alg_oid, tsa_digest_alg
        ),
    ));

    if let Some(leaf_cert) = tsa_signer_cert {
        let eku_ok = trust::cert_has_timestamp_eku(&leaf_cert);
        steps.push(Step::new(
            StepKind::TsaExtendedKeyUsage,
            if eku_ok {
                Status::Ok
            } else if require_timestamp_trust {
                Status::Fail
            } else {
                Status::Warn
            },
            if eku_ok {
                "id-kp-timeStamping"
            } else {
                "missing id-kp-timeStamping"
            },
        ));
        let intermediates: Vec<Vec<u8>> = tst_cms
            .certificates
            .iter()
            .filter(|cert| **cert != leaf_cert)
            .cloned()
            .collect();
        let validation_time = tst_info
            .as_ref()
            .and_then(|details| details.gen_time.as_deref())
            .and_then(crate::revocation::asn1_time_to_unix_seconds);
        let timestamp_trust_anchors = timestamp_trust_anchors_for_time(options, validation_time);
        let trusted_anchor_chain = trust::trusted_chain_to_anchor_at_time(
            &leaf_cert,
            &intermediates,
            &timestamp_trust_anchors,
            validation_time,
            validation_time,
        );
        let trusted_pin_chain = || {
            trust::trusted_chain_to_certificate_sha256_pin(
                &leaf_cert,
                &intermediates,
                &options.timestamp_certificate_sha256_pins,
            )
        };
        let (chain, trust_detail, chain_status) = if let Some(chain) = trusted_anchor_chain {
            (
                chain,
                "-> configured timestamp trust anchor".to_owned(),
                Status::Ok,
            )
        } else if let Some(chain) = trusted_pin_chain() {
            (
                chain,
                "-> configured timestamp certificate pin".to_owned(),
                Status::Ok,
            )
        } else {
            (
                trust::unique_certificates({
                    let mut chain = vec![leaf_cert.clone()];
                    chain.extend(intermediates);
                    chain
                }),
                "no path to configured timestamp trust anchors or pins".to_owned(),
                if require_timestamp_trust {
                    Status::Fail
                } else {
                    Status::Warn
                },
            )
        };
        steps.push(Step::new(
            StepKind::TsaCertificateChain,
            chain_status,
            trust_detail.clone(),
        ));
        Some(make_timestamp_details(
            tst_info,
            Some(leaf_cert),
            chain,
            Some(trust_detail),
        ))
    } else {
        let detail = "could not identify TSA signer cert by sid".to_owned();
        steps.push(Step::new(
            StepKind::TsaCertificateChain,
            if require_timestamp_trust {
                Status::Fail
            } else {
                Status::Warn
            },
            detail.clone(),
        ));
        Some(make_timestamp_details(tst_info, None, vec![], Some(detail)))
    }
}

pub fn verify_document_timestamp<F>(
    sig: &crate::pdf::SigDict,
    signed_data: &[u8],
    mut steps: Vec<Step>,
    make_report: F,
    options: &VerificationOptions,
) -> SignatureReport
where
    F: Fn(
        Vec<Step>,
        Option<String>,
        Option<String>,
        Option<CertificateDetails>,
        Vec<CertificateDetails>,
        Option<TimestampDetails>,
        Verdict,
    ) -> SignatureReport,
{
    let require_timestamp_trust = has_configured_timestamp_trust(options);
    let Some(tst_cms) = Cms::parse(&sig.cms_bytes) else {
        steps.push(Step::new(
            StepKind::DocumentTimestamp,
            Status::Fail,
            "RFC 3161 token could not be parsed",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    };
    steps.push(Step::new(
        StepKind::DocumentTimestamp,
        Status::Ok,
        format!(
            "RFC 3161 token, certs={}, digestAlg={}",
            tst_cms.certificates.len(),
            tst_cms.digest_alg_oid
        ),
    ));

    let Some(tst_signer) = tst_cms.signer_infos.first() else {
        steps.push(Step::new(
            StepKind::TsaTimestamp,
            Status::Fail,
            "TimeStampToken has no signerInfos",
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    };
    if tst_cms.e_content_type_oid != crate::cms::OID_TST_INFO {
        steps.push(Step::new(
            StepKind::DocumentTimestamp,
            Status::Fail,
            format!(
                "TimeStampToken eContentType is {}, expected {}",
                tst_cms.e_content_type_oid,
                crate::cms::OID_TST_INFO
            ),
        ));
        return make_report(steps, None, None, None, vec![], None, Verdict::Invalid);
    }
    let tst_info = tst_cms
        .e_content
        .as_deref()
        .and_then(parse_tst_info_details);
    let signing_time = tst_info
        .as_ref()
        .and_then(|details| details.gen_time.clone());

    let mut imprint_ok = false;
    let mut imprint_detail = "no TSTInfo eContent".to_owned();
    if let Some(details) = &tst_info {
        if let Some(computed) = crypto::digest(signed_data, &details.message_imprint_algorithm_oid)
        {
            imprint_ok = computed == details.message_imprint_hash;
            imprint_detail = format!(
                "{} over document timestamp ByteRange",
                crypto::digest_name(&details.message_imprint_algorithm_oid)
            );
        }
    }
    steps.push(Step::new(
        StepKind::TsaMessageImprint,
        if imprint_ok { Status::Ok } else { Status::Fail },
        imprint_detail,
    ));
    if !imprint_ok {
        return make_report(
            steps,
            None,
            signing_time,
            None,
            vec![],
            None,
            Verdict::Invalid,
        );
    }

    let tsa_signer_cert = tst_cms
        .cert_for_signer(tst_signer)
        .or_else(|| tst_cms.certificates.last().cloned());
    let tsa_digest_alg = if tst_signer.digest_alg_oid.is_empty() {
        &tst_cms.digest_alg_oid
    } else {
        &tst_signer.digest_alg_oid
    };
    let tsa_sig_ok = if let Some(cert) = &tsa_signer_cert {
        let mut tsa_input = tst_signer.signed_attrs_raw_bytes.clone();
        if !tsa_input.is_empty() {
            tsa_input[0] = 0x31;
        }
        crypto::verify_any_cms_signature(
            &tsa_input,
            &tst_signer.signature_alg_oid,
            tst_signer.signature_alg_params.as_deref(),
            tsa_digest_alg,
            &tst_signer.signature,
            cert,
        )
    } else {
        false
    };
    steps.push(Step::new(
        StepKind::TsaSignatureVerify,
        if tsa_sig_ok { Status::Ok } else { Status::Fail },
        format!(
            "sigAlg={} digest={}",
            tst_signer.signature_alg_oid, tsa_digest_alg
        ),
    ));
    if !tsa_sig_ok {
        return make_report(
            steps,
            None,
            signing_time,
            None,
            vec![],
            None,
            Verdict::Invalid,
        );
    }

    let timestamp_details = if let Some(leaf_cert) = tsa_signer_cert {
        let eku_ok = trust::cert_has_timestamp_eku(&leaf_cert);
        steps.push(Step::new(
            StepKind::TsaExtendedKeyUsage,
            if eku_ok {
                Status::Ok
            } else if require_timestamp_trust {
                Status::Fail
            } else {
                Status::Warn
            },
            if eku_ok {
                "id-kp-timeStamping"
            } else {
                "missing id-kp-timeStamping"
            },
        ));
        let intermediates: Vec<Vec<u8>> = tst_cms
            .certificates
            .iter()
            .filter(|cert| **cert != leaf_cert)
            .cloned()
            .collect();
        let validation_time = tst_info
            .as_ref()
            .and_then(|details| details.gen_time.as_deref())
            .and_then(crate::revocation::asn1_time_to_unix_seconds);
        let timestamp_trust_anchors = timestamp_trust_anchors_for_time(options, validation_time);
        let trusted_anchor_chain = trust::trusted_chain_to_anchor_at_time(
            &leaf_cert,
            &intermediates,
            &timestamp_trust_anchors,
            validation_time,
            validation_time,
        );
        let trusted_pin_chain = || {
            trust::trusted_chain_to_certificate_sha256_pin(
                &leaf_cert,
                &intermediates,
                &options.timestamp_certificate_sha256_pins,
            )
        };
        let (chain, trust_detail, status) = if let Some(chain) = trusted_anchor_chain {
            (
                chain,
                "-> configured timestamp trust anchor".to_owned(),
                Status::Ok,
            )
        } else if let Some(chain) = trusted_pin_chain() {
            (
                chain,
                "-> configured timestamp certificate pin".to_owned(),
                Status::Ok,
            )
        } else {
            (
                trust::unique_certificates({
                    let mut chain = vec![leaf_cert.clone()];
                    chain.extend(intermediates);
                    chain
                }),
                "no path to configured timestamp trust anchors or pins".to_owned(),
                if require_timestamp_trust {
                    Status::Fail
                } else {
                    Status::Warn
                },
            )
        };
        steps.push(Step::new(
            StepKind::TsaCertificateChain,
            status,
            trust_detail.clone(),
        ));
        Some(make_timestamp_details(
            tst_info,
            Some(leaf_cert),
            chain,
            Some(trust_detail),
        ))
    } else {
        steps.push(Step::new(
            StepKind::TsaCertificateChain,
            if require_timestamp_trust {
                Status::Fail
            } else {
                Status::Warn
            },
            "could not identify TSA signer cert by sid",
        ));
        Some(make_timestamp_details(
            tst_info,
            None,
            vec![],
            Some("could not identify TSA signer cert by sid".to_owned()),
        ))
    };

    let verdict = crate::report::verdict_for(&steps);
    make_report(
        steps,
        None,
        signing_time,
        None,
        vec![],
        timestamp_details,
        verdict,
    )
}

fn has_configured_timestamp_trust(options: &VerificationOptions) -> bool {
    !options.timestamp_trust_anchors.is_empty()
        || !options.timestamp_trust_anchor_sets.is_empty()
        || !options.timestamp_certificate_sha256_pins.is_empty()
}

fn parse_tst_info_details(der: &[u8]) -> Option<TstInfoDetails> {
    let mut reader = asn1::Reader::new(der);
    let outer = reader.read_tlv()?;
    if outer.tag != 0x30 {
        return None;
    }
    let mut inner = asn1::Reader::new(&outer.content);
    inner.skip_one_tlv();
    let policy_oid = inner
        .read_tlv()
        .filter(|tlv| tlv.tag == 0x06)
        .map(|tlv| asn1::oid_string(&tlv.content));
    let mi = inner.read_tlv()?;
    if mi.tag != 0x30 {
        return None;
    }
    let mut mi_reader = asn1::Reader::new(&mi.content);
    let alg = mi_reader.read_tlv()?;
    let message_imprint_algorithm_oid = crate::cms::algorithm_identifier_oid(&alg.content)?;
    let hashed = mi_reader.read_tlv()?;
    if hashed.tag != 0x04 {
        return None;
    }
    let serial_number_hex = inner
        .read_tlv()
        .filter(|tlv| tlv.tag == 0x02)
        .map(|tlv| hex::encode_upper(tlv.content));
    let gen_time = inner
        .read_tlv()
        .filter(|tlv| tlv.tag == 0x17 || tlv.tag == 0x18)
        .and_then(|tlv| String::from_utf8(tlv.content).ok());
    Some(TstInfoDetails {
        policy_oid,
        message_imprint_algorithm_oid,
        message_imprint_hash: hashed.content,
        serial_number_hex,
        gen_time,
    })
}

fn timestamp_trust_anchors_for_time(
    options: &VerificationOptions,
    validation_time: Option<f64>,
) -> Vec<Vec<u8>> {
    crate::trust_anchors_for_time(
        &options.timestamp_trust_anchors,
        &options.timestamp_trust_anchor_sets,
        validation_time,
    )
}

fn make_timestamp_details(
    tst_info: Option<TstInfoDetails>,
    tsa_signer_cert: Option<Vec<u8>>,
    tsa_chain: Vec<Vec<u8>>,
    trust_detail: Option<String>,
) -> TimestampDetails {
    TimestampDetails {
        timestamp_time: tst_info
            .as_ref()
            .and_then(|details| details.gen_time.clone()),
        policy_oid: tst_info
            .as_ref()
            .and_then(|details| details.policy_oid.clone()),
        serial_number_hex: tst_info
            .as_ref()
            .and_then(|details| details.serial_number_hex.clone()),
        message_imprint_algorithm: tst_info
            .as_ref()
            .map(|details| crypto::digest_name(&details.message_imprint_algorithm_oid).to_owned()),
        message_imprint_hash: tst_info
            .as_ref()
            .map(|details| hex::encode_upper(&details.message_imprint_hash)),
        tsa_certificate: tsa_signer_cert
            .as_deref()
            .and_then(trust::certificate_details),
        tsa_certificate_chain: trust::unique_certificates(tsa_chain)
            .iter()
            .filter_map(|cert| trust::certificate_details(cert))
            .collect(),
        trust_detail,
    }
}
