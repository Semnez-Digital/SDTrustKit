use crate::asn1::{self, Reader};

pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const OID_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
pub const OID_SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
pub const OID_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
pub const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cms {
    pub version: usize,
    pub digest_alg_oid: String,
    pub e_content_type_oid: String,
    pub e_content: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub signer_infos: Vec<SignerInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfo {
    pub version: usize,
    pub sid_issuer_der: Option<Vec<u8>>,
    pub sid_serial_bytes: Option<Vec<u8>>,
    pub sid_subject_key_identifier: Option<Vec<u8>>,
    pub digest_alg_oid: String,
    pub signed_attrs_raw_bytes: Vec<u8>,
    pub signed_attrs: Vec<(String, Vec<u8>)>,
    pub unsigned_attrs: Vec<(String, Vec<u8>)>,
    pub signature_alg_oid: String,
    pub signature_alg_params: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl SignerInfo {
    pub fn find_signed_attribute(&self, oid: &str) -> Option<&[u8]> {
        self.signed_attrs
            .iter()
            .find(|(attr_oid, _)| attr_oid == oid)
            .map(|(_, value)| value.as_slice())
    }

    pub fn count_signed_attribute(&self, oid: &str) -> usize {
        self.signed_attrs
            .iter()
            .filter(|(attr_oid, _)| attr_oid == oid)
            .count()
    }

    pub fn find_unsigned_attribute(&self, oid: &str) -> Option<&[u8]> {
        self.unsigned_attrs
            .iter()
            .find(|(attr_oid, _)| attr_oid == oid)
            .map(|(_, value)| value.as_slice())
    }

    fn parse(body: &[u8]) -> Option<Self> {
        let mut r = Reader::new(body);
        let version_tlv = r.read_tlv()?;
        if version_tlv.tag != 0x02 {
            return None;
        }
        let version = asn1::int_value(&version_tlv.content);
        let sid_tlv = r.read_tlv()?;
        let mut sid_issuer_der = None;
        let mut sid_serial_bytes = None;
        let mut sid_subject_key_identifier = None;
        if sid_tlv.tag == 0x30 {
            let mut sid_reader = Reader::new(&sid_tlv.content);
            sid_issuer_der = sid_reader.read_tlv().map(|issuer| issuer.full_bytes);
            if let Some(serial_tlv) = sid_reader.read_tlv() {
                if serial_tlv.tag == 0x02 {
                    sid_serial_bytes = Some(serial_tlv.content);
                }
            }
        } else if sid_tlv.tag == 0x80 {
            sid_subject_key_identifier = Some(sid_tlv.content);
        }

        let digest_alg_tlv = r.read_tlv()?;
        if digest_alg_tlv.tag != 0x30 {
            return None;
        }
        let digest_alg_oid = algorithm_identifier_oid(&digest_alg_tlv.content)?;

        let mut signed_attrs_raw_bytes = Vec::new();
        let mut signed_attrs = Vec::new();
        if r.peek_tag() == Some(0xa0) {
            let sa = r.read_tlv()?;
            signed_attrs_raw_bytes =
                der_encoded_signed_attributes(&sa.content).unwrap_or(sa.full_bytes);
            let mut ar = Reader::new(&sa.content);
            while let Some(att) = ar.read_tlv() {
                if att.tag != 0x30 {
                    continue;
                }
                if let Some((oid, value)) = parse_attribute(&att.content, false) {
                    signed_attrs.push((oid, value));
                }
            }
        }

        let sig_alg_tlv = r.read_tlv()?;
        if sig_alg_tlv.tag != 0x30 {
            return None;
        }
        let (signature_alg_oid, signature_alg_params) =
            algorithm_identifier_oid_and_params(&sig_alg_tlv.content)?;
        let sig_tlv = r.read_tlv()?;
        if sig_tlv.tag != 0x04 {
            return None;
        }
        let signature = sig_tlv.content;

        let mut unsigned_attrs = Vec::new();
        if let Some(ua) = r.read_tlv() {
            if ua.tag == 0xa1 {
                let mut ur = Reader::new(&ua.content);
                while let Some(att) = ur.read_tlv() {
                    if att.tag != 0x30 {
                        continue;
                    }
                    if let Some((oid, value)) = parse_attribute(&att.content, true) {
                        unsigned_attrs.push((oid, value));
                    }
                }
            }
        }

        Some(Self {
            version,
            sid_issuer_der,
            sid_serial_bytes,
            sid_subject_key_identifier,
            digest_alg_oid,
            signed_attrs_raw_bytes,
            signed_attrs,
            unsigned_attrs,
            signature_alg_oid,
            signature_alg_params,
            signature,
        })
    }
}

impl Cms {
    pub fn parse(cms_der: &[u8]) -> Option<Self> {
        let mut r = Reader::new(cms_der);
        let outer = r.read_tlv()?;
        if outer.tag != 0x30 {
            return None;
        }
        let mut outer_r = Reader::new(&outer.content);
        let ct_tlv = outer_r.read_tlv()?;
        if ct_tlv.tag != 0x06 || asn1::oid_string(&ct_tlv.content) != OID_SIGNED_DATA {
            return None;
        }
        let expl = outer_r.read_tlv()?;
        if expl.tag != 0xa0 {
            return None;
        }
        let mut inner = Reader::new(&expl.content);
        let sd = inner.read_tlv()?;
        if sd.tag != 0x30 {
            return None;
        }
        let mut sd_r = Reader::new(&sd.content);
        let version_tlv = sd_r.read_tlv()?;
        if version_tlv.tag != 0x02 {
            return None;
        }
        let version = asn1::int_value(&version_tlv.content);
        let d_algs_tlv = sd_r.read_tlv()?;
        if d_algs_tlv.tag != 0x31 {
            return None;
        }
        let mut digest_alg_oid = String::new();
        let mut d_r = Reader::new(&d_algs_tlv.content);
        if let Some(first_alg) = d_r.read_tlv() {
            if first_alg.tag == 0x30 {
                digest_alg_oid = algorithm_identifier_oid(&first_alg.content).unwrap_or_default();
            }
        }

        let encap = sd_r.read_tlv()?;
        if encap.tag != 0x30 {
            return None;
        }
        let mut er = Reader::new(&encap.content);
        let oid_tlv = er.read_tlv()?;
        if oid_tlv.tag != 0x06 {
            return None;
        }
        let e_content_type_oid = asn1::oid_string(&oid_tlv.content);
        let mut e_content = None;
        if let Some(exp) = er.read_tlv() {
            if exp.tag == 0xa0 {
                let mut inner_r = Reader::new(&exp.content);
                if let Some(os) = inner_r.read_tlv() {
                    if os.tag == 0x04 {
                        e_content = Some(os.content);
                    }
                }
            }
        }

        let mut certificates = Vec::new();
        let mut signer_infos = Vec::new();
        while let Some(next) = sd_r.read_tlv() {
            match next.tag {
                0xa0 => {
                    let mut cr = Reader::new(&next.content);
                    while let Some(cert) = cr.read_tlv() {
                        if cert.tag == 0x30 {
                            certificates.push(cert.full_bytes);
                        }
                    }
                }
                0xa1 => {}
                0x31 => {
                    let mut sir = Reader::new(&next.content);
                    while let Some(si_tlv) = sir.read_tlv() {
                        if si_tlv.tag == 0x30 {
                            if let Some(si) = SignerInfo::parse(&si_tlv.content) {
                                signer_infos.push(si);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Some(Self {
            version,
            digest_alg_oid,
            e_content_type_oid,
            e_content,
            certificates,
            signer_infos,
        })
    }

    pub fn cert_for_signer(&self, si: &SignerInfo) -> Option<Vec<u8>> {
        if let (Some(target_issuer), Some(target_serial)) =
            (&si.sid_issuer_der, &si.sid_serial_bytes)
        {
            for cert in &self.certificates {
                if extract_cert_issuer_serial(cert).as_ref()
                    == Some(&(target_issuer.clone(), target_serial.clone()))
                {
                    return Some(cert.clone());
                }
            }
        }
        if let Some(target_ski) = &si.sid_subject_key_identifier {
            for cert in &self.certificates {
                if extract_subject_key_identifier(cert).as_ref() == Some(target_ski) {
                    return Some(cert.clone());
                }
            }
        }
        None
    }
}

fn der_encoded_signed_attributes(content: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(content);
    let mut attrs = Vec::new();
    while let Some(attr) = reader.read_tlv() {
        if attr.tag != 0x30 {
            return None;
        }
        attrs.push(attr.full_bytes);
    }
    if attrs.is_empty() {
        return None;
    }
    attrs.sort();

    let body_len = attrs.iter().map(Vec::len).sum();
    let mut out = vec![0x31];
    out.extend(asn1::der_length(body_len));
    for attr in attrs {
        out.extend(attr);
    }
    Some(out)
}

pub fn algorithm_identifier_oid(data: &[u8]) -> Option<String> {
    algorithm_identifier_oid_and_params(data).map(|(oid, _)| oid)
}

pub fn algorithm_identifier_oid_and_params(data: &[u8]) -> Option<(String, Option<Vec<u8>>)> {
    let mut reader = Reader::new(data);
    let oid = reader.read_tlv()?;
    if oid.tag != 0x06 {
        return None;
    }
    Some((
        asn1::oid_string(&oid.content),
        reader.read_tlv().map(|tlv| tlv.full_bytes),
    ))
}

fn parse_attribute(data: &[u8], unwrap_first_value: bool) -> Option<(String, Vec<u8>)> {
    let mut reader = Reader::new(data);
    let oid_tlv = reader.read_tlv()?;
    if oid_tlv.tag != 0x06 {
        return None;
    }
    let set_tlv = reader.read_tlv()?;
    if set_tlv.tag != 0x31 {
        return None;
    }
    let value = if unwrap_first_value {
        let mut inner = Reader::new(&set_tlv.content);
        inner
            .read_tlv()
            .map(|tlv| tlv.full_bytes)
            .unwrap_or(set_tlv.content)
    } else {
        set_tlv.content
    };
    Some((asn1::oid_string(&oid_tlv.content), value))
}

fn extract_cert_issuer_serial(cert_der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut r = Reader::new(cert_der);
    let cert = r.read_tlv()?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut cert_reader = Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut body = Reader::new(&tbs.content);
    if body.peek_tag() == Some(0xa0) {
        let _ = body.read_tlv();
    }
    let serial = body.read_tlv()?;
    if serial.tag != 0x02 {
        return None;
    }
    let _signature_algorithm = body.read_tlv()?;
    let issuer = body.read_tlv()?;
    if issuer.tag != 0x30 {
        return None;
    }
    Some((issuer.full_bytes, serial.content))
}

fn extract_subject_key_identifier(cert_der: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(cert_der);
    let cert = r.read_tlv()?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut cert_reader = Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut tbs_reader = Reader::new(&tbs.content);
    if tbs_reader.peek_tag() == Some(0xa0) {
        let _ = tbs_reader.read_tlv();
    }
    for _ in 0..6 {
        if !tbs_reader.skip_one_tlv() {
            return None;
        }
    }
    while let Some(field) = tbs_reader.read_tlv() {
        if field.tag != 0xa3 {
            continue;
        }
        let mut extensions_reader = Reader::new(&field.content);
        let extensions = extensions_reader.read_tlv()?;
        if extensions.tag != 0x30 {
            return None;
        }
        let mut extension_list = Reader::new(&extensions.content);
        while let Some(ext) = extension_list.read_tlv() {
            if ext.tag != 0x30 {
                continue;
            }
            let mut ext_reader = Reader::new(&ext.content);
            let oid_tlv = ext_reader.read_tlv()?;
            if oid_tlv.tag != 0x06
                || asn1::oid_string(&oid_tlv.content) != OID_SUBJECT_KEY_IDENTIFIER
            {
                continue;
            }
            if ext_reader.peek_tag() == Some(0x01) {
                let _ = ext_reader.read_tlv();
            }
            let value = ext_reader.read_tlv()?;
            if value.tag != 0x04 {
                return None;
            }
            let mut value_reader = Reader::new(&value.content);
            let ski = value_reader.read_tlv()?;
            return (ski.tag == 0x04).then_some(ski.content);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &[u8] = include_bytes!(
        "../tests/fixtures/app_trust_anchors/aa53228264e1dd6adb08194fe4c931bd7fd1c54c59b26445409058a8846d4c24-sts-root-g2.der"
    );

    #[test]
    fn signer_certificate_matches_issuer_and_serial_together() {
        let (issuer, serial) = extract_cert_issuer_serial(CERT).expect("issuer and serial");
        let cms = Cms {
            version: 1,
            digest_alg_oid: String::new(),
            e_content_type_oid: OID_DATA.to_owned(),
            e_content: None,
            certificates: vec![CERT.to_vec()],
            signer_infos: vec![],
        };

        assert_eq!(
            cms.cert_for_signer(&signer_with_issuer_and_serial(issuer, serial)),
            Some(CERT.to_vec())
        );
    }

    #[test]
    fn signer_certificate_does_not_match_serial_with_wrong_issuer() {
        let (mut issuer, serial) = extract_cert_issuer_serial(CERT).expect("issuer and serial");
        let last = issuer.len() - 1;
        issuer[last] ^= 0x01;
        let cms = Cms {
            version: 1,
            digest_alg_oid: String::new(),
            e_content_type_oid: OID_DATA.to_owned(),
            e_content: None,
            certificates: vec![CERT.to_vec()],
            signer_infos: vec![],
        };

        assert_eq!(
            cms.cert_for_signer(&signer_with_issuer_and_serial(issuer, serial)),
            None
        );
    }

    fn signer_with_issuer_and_serial(issuer: Vec<u8>, serial: Vec<u8>) -> SignerInfo {
        SignerInfo {
            version: 1,
            sid_issuer_der: Some(issuer),
            sid_serial_bytes: Some(serial),
            sid_subject_key_identifier: None,
            digest_alg_oid: String::new(),
            signed_attrs_raw_bytes: vec![],
            signed_attrs: vec![],
            unsigned_attrs: vec![],
            signature_alg_oid: String::new(),
            signature_alg_params: None,
            signature: vec![],
        }
    }
}
