use crate::report::CertificateDetails;
use crate::{asn1, crypto};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const OID_EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const OID_EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
const OID_EKU_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const OID_EKU_MS_DOCUMENT_SIGNING: &str = "1.3.6.1.4.1.311.10.3.12";

#[derive(Clone)]
struct ParsedCertificate {
    der: Vec<u8>,
    tbs: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: Option<f64>,
    not_after: Option<f64>,
    signature_alg_oid: String,
    signature_alg_params: Option<Vec<u8>>,
    signature: Vec<u8>,
    basic_constraints_allows_ca: Option<bool>,
    key_usage_allows_certificate_signing: Option<bool>,
}

#[cfg(test)]
pub fn trusted_chain_to_anchor(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
) -> Option<Vec<Vec<u8>>> {
    if anchors.is_empty() {
        return None;
    }
    if anchors.iter().any(|anchor| anchor.as_slice() == leaf) {
        return Some(vec![leaf.to_vec()]);
    }
    trusted_chain_to_anchor_at_time(leaf, intermediates, anchors, None, None)
}

pub fn trusted_chain_to_anchor_at_time(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    leaf_validation_time: Option<f64>,
    issuer_validation_time: Option<f64>,
) -> Option<Vec<Vec<u8>>> {
    if anchors.is_empty() {
        return None;
    }
    if anchors.iter().any(|anchor| anchor.as_slice() == leaf) {
        return Some(vec![leaf.to_vec()]);
    }
    manual_trusted_chain_to_anchor(
        leaf,
        intermediates,
        anchors,
        &[],
        leaf_validation_time,
        issuer_validation_time,
    )
}

pub fn trusted_chain_to_anchor_with_preferred_anchors_at_time(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    preferred_anchors: &[Vec<u8>],
    leaf_validation_time: Option<f64>,
    issuer_validation_time: Option<f64>,
) -> Option<Vec<Vec<u8>>> {
    if anchors.is_empty() {
        return None;
    }
    if anchors.iter().any(|anchor| anchor.as_slice() == leaf) {
        return Some(vec![leaf.to_vec()]);
    }
    manual_trusted_chain_to_anchor(
        leaf,
        intermediates,
        anchors,
        preferred_anchors,
        leaf_validation_time,
        issuer_validation_time,
    )
}

pub fn trusted_chain_to_certificate_sha256_pin(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    sha256_pins: &[String],
) -> Option<Vec<Vec<u8>>> {
    if sha256_pins.is_empty() {
        return None;
    }
    let mut certificates = vec![leaf.to_vec()];
    certificates.extend(intermediates.iter().cloned());
    if certificates.iter().any(|cert| {
        let fingerprint = fingerprint_plain(Sha256::digest(cert));
        sha256_pins
            .iter()
            .any(|pin| fingerprint.eq_ignore_ascii_case(&pin.replace(':', "")))
    }) {
        let mut chain = vec![leaf.to_vec()];
        chain.extend(intermediates.iter().cloned());
        return Some(unique_certificates(chain));
    }
    None
}

fn manual_trusted_chain_to_anchor(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    preferred_anchors: &[Vec<u8>],
    leaf_validation_time: Option<f64>,
    issuer_validation_time: Option<f64>,
) -> Option<Vec<Vec<u8>>> {
    let mut all = vec![leaf.to_vec()];
    all.extend(intermediates.iter().cloned());
    all.extend(anchors.iter().cloned());
    let certs: Vec<ParsedCertificate> = unique_certificates(all)
        .iter()
        .filter_map(|cert| parse_certificate_for_chain(cert))
        .collect();
    let anchor_set = anchors.to_vec();
    let preferred_anchor_set = preferred_anchors.to_vec();
    let mut chain = vec![certs.iter().find(|cert| cert.der == leaf)?.clone()];
    let mut current = chain[0].clone();
    let mut visited = vec![current.der.clone()];
    for _ in 0..certs.len() {
        if chain.len() > 1 && anchor_set.contains(&current.der) {
            return Some(chain.into_iter().map(|cert| cert.der).collect());
        }
        let mut candidates = certs
            .iter()
            .filter(|candidate| {
                candidate.der != current.der
                    && candidate.subject == current.issuer
                    && !visited.contains(&candidate.der)
            })
            .collect::<Vec<_>>();
        if !preferred_anchor_set.is_empty() {
            candidates.sort_by_key(|candidate| {
                (
                    !(preferred_anchor_set.contains(&candidate.der)
                        && candidate.subject == candidate.issuer),
                    !preferred_anchor_set.contains(&candidate.der),
                )
            });
        }
        let issuer = candidates.into_iter().find(|candidate| {
            let current_validation_time = if chain.len() == 1 {
                leaf_validation_time
            } else {
                issuer_validation_time
            };
            let candidate_validation_time = if anchor_set.contains(&candidate.der) {
                None
            } else {
                issuer_validation_time
            };
            certificate_is_valid_at(&current, current_validation_time)
                && certificate_is_valid_at(candidate, candidate_validation_time)
                && certificate_can_delegate(candidate)
                && verify_certificate_signature(&current, candidate)
        })?;
        chain.push(issuer.clone());
        visited.push(issuer.der.clone());
        current = issuer.clone();
    }
    None
}

fn parse_certificate_for_chain(der: &[u8]) -> Option<ParsedCertificate> {
    let mut reader = asn1::Reader::new(der);
    let cert = reader.read_tlv()?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut cert_reader = asn1::Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    let sig_alg = cert_reader.read_tlv()?;
    let sig_value = cert_reader.read_tlv()?;
    if tbs.tag != 0x30
        || sig_alg.tag != 0x30
        || sig_value.tag != 0x03
        || sig_value.content.is_empty()
    {
        return None;
    }
    let mut tbs_reader = asn1::Reader::new(&tbs.content);
    if tbs_reader.peek_tag() == Some(0xa0) {
        let _ = tbs_reader.read_tlv();
    }
    tbs_reader.skip_one_tlv();
    tbs_reader.skip_one_tlv();
    let issuer = tbs_reader.read_tlv()?;
    let validity = tbs_reader.read_tlv()?;
    let subject = tbs_reader.read_tlv()?;
    let mut validity_reader = asn1::Reader::new(&validity.content);
    let not_before = validity_reader
        .read_tlv()
        .as_ref()
        .and_then(time_tlv_to_unix_seconds);
    let not_after = validity_reader
        .read_tlv()
        .as_ref()
        .and_then(time_tlv_to_unix_seconds);
    let _ = tbs_reader.skip_one_tlv();
    let mut basic_constraints_allows_ca = None;
    let mut key_usage_allows_certificate_signing = None;
    while let Some(field) = tbs_reader.read_tlv() {
        if field.tag != 0xa3 {
            continue;
        }
        let mut extensions_reader = asn1::Reader::new(&field.content);
        let Some(extensions) = extensions_reader.read_tlv() else {
            continue;
        };
        let mut extension_list = asn1::Reader::new(&extensions.content);
        while let Some(ext) = extension_list.read_tlv() {
            if ext.tag != 0x30 {
                continue;
            }
            let mut ext_reader = asn1::Reader::new(&ext.content);
            let Some(oid_tlv) = ext_reader.read_tlv() else {
                continue;
            };
            if oid_tlv.tag != 0x06 {
                continue;
            }
            let oid = asn1::oid_string(&oid_tlv.content);
            if ext_reader.peek_tag() == Some(0x01) {
                let _ = ext_reader.read_tlv();
            }
            let Some(value) = ext_reader.read_tlv() else {
                continue;
            };
            if value.tag != 0x04 {
                continue;
            }
            match oid.as_str() {
                "2.5.29.19" => {
                    basic_constraints_allows_ca =
                        basic_constraints_allows_certificate_authority(&value.content);
                }
                "2.5.29.15" => {
                    key_usage_allows_certificate_signing =
                        Some(key_usage_contains_bit(&value.content, 5));
                }
                _ => {}
            }
        }
    }
    let (signature_alg_oid, signature_alg_params) =
        crate::cms::algorithm_identifier_oid_and_params(&sig_alg.content)?;
    Some(ParsedCertificate {
        der: der.to_vec(),
        tbs: tbs.full_bytes,
        issuer: issuer.full_bytes,
        subject: subject.full_bytes,
        not_before,
        not_after,
        signature_alg_oid,
        signature_alg_params,
        signature: sig_value.content[1..].to_vec(),
        basic_constraints_allows_ca,
        key_usage_allows_certificate_signing,
    })
}

fn certificate_is_valid_at(cert: &ParsedCertificate, validation_time: Option<f64>) -> bool {
    let Some(validation_time) = validation_time else {
        return true;
    };
    if cert
        .not_before
        .is_some_and(|not_before| validation_time < not_before)
    {
        return false;
    }
    if cert
        .not_after
        .is_some_and(|not_after| validation_time > not_after)
    {
        return false;
    }
    true
}

pub fn certificate_is_valid_at_unix_time(cert_der: &[u8], validation_time: f64) -> Option<bool> {
    parse_certificate_for_chain(cert_der)
        .map(|cert| certificate_is_valid_at(&cert, Some(validation_time)))
}

fn certificate_can_delegate(cert: &ParsedCertificate) -> bool {
    if let Some(allows_ca) = cert.basic_constraints_allows_ca {
        return allows_ca && cert.key_usage_allows_certificate_signing.unwrap_or(true);
    }
    cert.key_usage_allows_certificate_signing == Some(true)
}

fn time_tlv_to_unix_seconds(tlv: &asn1::Tlv) -> Option<f64> {
    if tlv.tag != 0x17 && tlv.tag != 0x18 {
        return None;
    }
    let raw = String::from_utf8(tlv.content.clone()).ok()?;
    crate::revocation::asn1_time_to_unix_seconds(&raw)
}

fn basic_constraints_allows_certificate_authority(der: &[u8]) -> Option<bool> {
    let mut reader = asn1::Reader::new(der);
    let sequence = reader.read_tlv()?;
    if sequence.tag != 0x30 {
        return None;
    }
    let mut body = asn1::Reader::new(&sequence.content);
    let Some(ca) = body.read_tlv() else {
        return Some(false);
    };
    if ca.tag != 0x01 {
        return Some(false);
    }
    Some(ca.content.first().is_some_and(|value| *value != 0))
}

fn key_usage_contains_bit(der: &[u8], index: usize) -> bool {
    let mut reader = asn1::Reader::new(der);
    let Some(bit_string) = reader.read_tlv() else {
        return false;
    };
    if bit_string.tag != 0x03 || bit_string.content.len() < 2 {
        return false;
    }
    let unused_bits = usize::from(bit_string.content[0]);
    let bytes = &bit_string.content[1..];
    let bit_count = bytes.len().saturating_mul(8).saturating_sub(unused_bits);
    if index >= bit_count {
        return false;
    }
    let byte = bytes[index / 8];
    let mask = 0x80 >> (index % 8);
    byte & mask != 0
}

fn verify_certificate_signature(child: &ParsedCertificate, issuer: &ParsedCertificate) -> bool {
    let digest_oid = crypto::normalized_digest_oid(&child.signature_alg_oid).to_string();
    let Some(digest) = crypto::digest(&child.tbs, &digest_oid) else {
        return false;
    };
    crypto::verify_signature_digest(
        &child.signature_alg_oid,
        child.signature_alg_params.as_deref(),
        &digest_oid,
        &digest,
        &child.signature,
        &issuer.der,
    )
}

pub fn certificate_details(der: &[u8]) -> Option<CertificateDetails> {
    let (serial, issuer, subject) = certificate_serial_issuer_subject(der)?;
    let subject_attrs = name_attributes(&subject);
    let issuer_attrs = name_attributes(&issuer);
    let common_name = subject_attrs
        .iter()
        .find(|(oid, _)| oid == OID_COMMON_NAME)
        .map(|(_, value)| value.clone());
    Some(CertificateDetails {
        der: der.to_vec(),
        subject_summary: name_summary(&subject_attrs),
        issuer_summary: name_summary(&issuer_attrs),
        common_name,
        serial_number_hex: normalized_hex(&serial),
        sha1_fingerprint: fingerprint_colon(Sha1::digest(der)),
        sha256_fingerprint: fingerprint_colon(Sha256::digest(der)),
    })
}

pub fn certificate_common_name(der: &[u8]) -> Option<String> {
    certificate_details(der).and_then(|details| details.common_name)
}

pub fn cert_has_extended_key_usage(cert_der: &[u8], target_oid: &str) -> bool {
    let Some(extensions) = certificate_extensions(cert_der) else {
        return false;
    };
    for ext in extensions {
        let mut ext_reader = asn1::Reader::new(&ext);
        let Some(oid_tlv) = ext_reader.read_tlv() else {
            continue;
        };
        if oid_tlv.tag != 0x06 || asn1::oid_string(&oid_tlv.content) != OID_EXTENDED_KEY_USAGE {
            continue;
        }
        if ext_reader.peek_tag() == Some(0x01) {
            let _ = ext_reader.read_tlv();
        }
        let Some(value) = ext_reader.read_tlv() else {
            return false;
        };
        let mut eku_reader = asn1::Reader::new(&value.content);
        let Some(seq) = eku_reader.read_tlv() else {
            return false;
        };
        let mut purposes = asn1::Reader::new(&seq.content);
        while let Some(purpose) = purposes.read_tlv() {
            if purpose.tag == 0x06 && asn1::oid_string(&purpose.content) == target_oid {
                return true;
            }
        }
        return false;
    }
    false
}

pub fn cert_has_timestamp_eku(cert_der: &[u8]) -> bool {
    cert_has_extended_key_usage(cert_der, OID_EKU_TIME_STAMPING)
}

pub fn cert_allows_document_signing_key_usage(cert_der: &[u8]) -> Option<bool> {
    let extensions = certificate_extensions(cert_der)?;
    for ext in extensions {
        let mut ext_reader = asn1::Reader::new(&ext);
        let oid_tlv = ext_reader.read_tlv()?;
        if oid_tlv.tag != 0x06 || asn1::oid_string(&oid_tlv.content) != "2.5.29.15" {
            continue;
        }
        if ext_reader.peek_tag() == Some(0x01) {
            let _ = ext_reader.read_tlv();
        }
        let value = ext_reader.read_tlv()?;
        if value.tag != 0x04 {
            return Some(false);
        }
        return Some(
            key_usage_contains_bit(&value.content, 0) || key_usage_contains_bit(&value.content, 1),
        );
    }
    Some(true)
}

pub fn cert_allows_document_signing_extended_key_usage(cert_der: &[u8]) -> Option<bool> {
    let purposes = cert_extended_key_usage_oids(cert_der)?;
    if purposes.is_empty() {
        return Some(true);
    }
    Some(purposes.iter().any(|oid| {
        oid == OID_EKU_EMAIL_PROTECTION
            || oid == OID_EKU_CODE_SIGNING
            || oid == OID_EKU_MS_DOCUMENT_SIGNING
    }))
}

fn cert_extended_key_usage_oids(cert_der: &[u8]) -> Option<Vec<String>> {
    let extensions = certificate_extensions(cert_der)?;
    for ext in extensions {
        let mut ext_reader = asn1::Reader::new(&ext);
        let oid_tlv = ext_reader.read_tlv()?;
        if oid_tlv.tag != 0x06 || asn1::oid_string(&oid_tlv.content) != OID_EXTENDED_KEY_USAGE {
            continue;
        }
        if ext_reader.peek_tag() == Some(0x01) {
            let _ = ext_reader.read_tlv();
        }
        let value = ext_reader.read_tlv()?;
        if value.tag != 0x04 {
            return Some(Vec::new());
        }
        let mut eku_reader = asn1::Reader::new(&value.content);
        let seq = eku_reader.read_tlv()?;
        if seq.tag != 0x30 {
            return Some(Vec::new());
        }
        let mut purposes = asn1::Reader::new(&seq.content);
        let mut out = Vec::new();
        while let Some(purpose) = purposes.read_tlv() {
            if purpose.tag == 0x06 {
                out.push(asn1::oid_string(&purpose.content));
            }
        }
        return Some(out);
    }
    Some(Vec::new())
}

fn certificate_serial_issuer_subject(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut reader = asn1::Reader::new(der);
    let cert = reader.read_tlv()?;
    let mut cert_reader = asn1::Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    let mut tbs_reader = asn1::Reader::new(&tbs.content);
    if tbs_reader.peek_tag() == Some(0xa0) {
        let _ = tbs_reader.read_tlv();
    }
    let serial = tbs_reader.read_tlv()?;
    tbs_reader.skip_one_tlv();
    let issuer = tbs_reader.read_tlv()?;
    tbs_reader.skip_one_tlv();
    let subject = tbs_reader.read_tlv()?;
    Some((serial.content, issuer.content, subject.content))
}

fn certificate_extensions(der: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut reader = asn1::Reader::new(der);
    let cert = reader.read_tlv()?;
    let mut cert_reader = asn1::Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    let mut tbs_reader = asn1::Reader::new(&tbs.content);
    if tbs_reader.peek_tag() == Some(0xa0) {
        let _ = tbs_reader.read_tlv();
    }
    for _ in 0..6 {
        tbs_reader.skip_one_tlv();
    }
    while let Some(field) = tbs_reader.read_tlv() {
        if field.tag != 0xa3 {
            continue;
        }
        let mut extensions_reader = asn1::Reader::new(&field.content);
        let extensions = extensions_reader.read_tlv()?;
        let mut extension_list = asn1::Reader::new(&extensions.content);
        let mut out = Vec::new();
        while let Some(ext) = extension_list.read_tlv() {
            if ext.tag == 0x30 {
                out.push(ext.content);
            }
        }
        return Some(out);
    }
    None
}

fn name_attributes(data: &[u8]) -> Vec<(String, String)> {
    let mut rdn_reader = asn1::Reader::new(data);
    let mut attrs = Vec::new();
    while let Some(rdn) = rdn_reader.read_tlv() {
        if rdn.tag != 0x31 {
            continue;
        }
        let mut set_reader = asn1::Reader::new(&rdn.content);
        while let Some(attr) = set_reader.read_tlv() {
            if attr.tag != 0x30 {
                continue;
            }
            let mut attr_reader = asn1::Reader::new(&attr.content);
            let Some(oid_tlv) = attr_reader.read_tlv() else {
                continue;
            };
            let Some(value_tlv) = attr_reader.read_tlv() else {
                continue;
            };
            if oid_tlv.tag == 0x06 {
                if let Some(value) = certificate_string(&value_tlv) {
                    attrs.push((asn1::oid_string(&oid_tlv.content), value));
                }
            }
        }
    }
    attrs
}

fn name_summary(attrs: &[(String, String)]) -> String {
    let preferred = [
        OID_COMMON_NAME,
        "1.2.840.113549.1.9.1",
        "2.5.4.10",
        "2.5.4.11",
        "2.5.4.6",
        "2.5.4.97",
    ];
    let mut parts = Vec::new();
    for oid in preferred {
        if let Some((_, value)) = attrs.iter().find(|(attr_oid, _)| attr_oid == oid) {
            parts.push(value.clone());
        }
    }
    if parts.is_empty() {
        attrs
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        parts.join(", ")
    }
}

fn certificate_string(tlv: &asn1::Tlv) -> Option<String> {
    match tlv.tag {
        0x0c | 0x13 | 0x16 | 0x14 => String::from_utf8(tlv.content.clone()).ok(),
        0x1e => {
            if !tlv.content.len().is_multiple_of(2) {
                return None;
            }
            let mut out = String::new();
            for bytes in tlv.content.chunks(2) {
                let value = u16::from_be_bytes([bytes[0], bytes[1]]);
                out.push(char::from_u32(u32::from(value))?);
            }
            Some(out)
        }
        _ => None,
    }
}

fn normalized_hex(data: &[u8]) -> String {
    let mut bytes = data.to_vec();
    while bytes.len() > 1 && bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    hex::encode_upper(bytes)
}

fn fingerprint_colon(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn fingerprint_plain(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>()
}

pub fn unique_certificates(certs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for cert in certs {
        if !out.contains(&cert) {
            out.push(cert);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        trusted_chain_to_anchor, trusted_chain_to_anchor_at_time,
        trusted_chain_to_certificate_sha256_pin,
    };
    use base64::Engine;
    use std::fs;
    use std::path::Path;

    const CALLER_SUPPLIED_CERT: &[u8] = include_bytes!(
        "../tests/fixtures/app_trust_anchors/aa53228264e1dd6adb08194fe4c931bd7fd1c54c59b26445409058a8846d4c24-sts-root-g2.der"
    );
    const CALLER_SUPPLIED_CERT_SHA256: &str =
        "AA53228264E1DD6ADB08194FE4C931BD7FD1C54C59B26445409058A8846D4C24";

    #[test]
    fn caller_supplied_anchor_can_be_the_leaf_certificate() {
        let chain =
            trusted_chain_to_anchor(CALLER_SUPPLIED_CERT, &[], &[CALLER_SUPPLIED_CERT.to_vec()])
                .expect("leaf anchor should be trusted");

        assert_eq!(chain, vec![CALLER_SUPPLIED_CERT.to_vec()]);
    }

    #[test]
    fn caller_supplied_certificate_pin_can_match_the_leaf_certificate() {
        let chain = trusted_chain_to_certificate_sha256_pin(
            CALLER_SUPPLIED_CERT,
            &[],
            &[CALLER_SUPPLIED_CERT_SHA256.to_owned()],
        )
        .expect("leaf pin should be trusted");

        assert_eq!(chain, vec![CALLER_SUPPLIED_CERT.to_vec()]);
    }

    #[test]
    fn caller_supplied_anchor_chain_checks_issuer_validity_when_requested() {
        let pdf = fs::read(fixture_path("pdf_model_gaps/control-valid.pdf")).expect("read PDF");
        let sig = crate::pdf::SigDict::parse_all(&pdf)
            .into_iter()
            .find(|sig| !sig.is_document_timestamp())
            .expect("document signature");
        let cms = crate::cms::Cms::parse(&sig.cms_bytes).expect("CMS");
        let signer = cms.signer_infos.first().expect("signerInfo");
        let signer_cert = cms.cert_for_signer(signer).expect("signer cert");
        let intermediates = cms
            .certificates
            .iter()
            .filter(|cert| **cert != signer_cert)
            .cloned()
            .collect::<Vec<_>>();
        let anchors = vec![read_pem_der(fixture_path("pdf_model_gaps/root.cert.pem"))];

        assert!(trusted_chain_to_anchor_at_time(
            &signer_cert,
            &intermediates,
            &anchors,
            None,
            None
        )
        .is_some());
        assert!(trusted_chain_to_anchor_at_time(
            &signer_cert,
            &intermediates,
            &anchors,
            None,
            Some(4_102_444_800.0),
        )
        .is_none());
    }

    fn read_pem_der(path: impl AsRef<Path>) -> Vec<u8> {
        let pem = fs::read_to_string(path).expect("read PEM");
        let encoded: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("decode PEM")
    }

    fn fixture_path(relative: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(relative)
    }
}
