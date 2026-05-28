use crate::{asn1, cms};
use rsa::pss;
use rsa::signature::hazmat::PrehashVerifier;
use rsa::{BigUint, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub const OID_SHA1: &str = "1.3.14.3.2.26";
pub const OID_SHA224: &str = "2.16.840.1.101.3.4.2.4";
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub const OID_ECDSA_PLAIN_SHA256: &str = "0.4.0.127.0.7.1.1.4.1.3";
pub const OID_ECDSA_PLAIN_SHA384: &str = "0.4.0.127.0.7.1.1.4.1.4";
pub const OID_ECDSA_PLAIN_SHA512: &str = "0.4.0.127.0.7.1.1.4.1.5";
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
pub const OID_RSA_SHA1: &str = "1.2.840.113549.1.1.5";
pub const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
pub const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
pub const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";
pub const OID_ECDSA_SHA1: &str = "1.2.840.10045.4.1";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
pub const OID_SECP384R1: &str = "1.3.132.0.34";
pub const OID_BRAINPOOL_P256R1: &str = "1.3.36.3.3.2.8.1.1.7";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";

pub fn digest(data: &[u8], oid: &str) -> Option<Vec<u8>> {
    match oid {
        OID_SHA1 => Some(Sha1::digest(data).to_vec()),
        OID_SHA256 => Some(Sha256::digest(data).to_vec()),
        OID_SHA384 => Some(Sha384::digest(data).to_vec()),
        OID_SHA512 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

pub fn digest_name(oid: &str) -> &'static str {
    match oid {
        OID_SHA1 => "SHA-1",
        OID_SHA224 => "SHA-224",
        OID_SHA256 => "SHA-256",
        OID_SHA384 => "SHA-384",
        OID_SHA512 => "SHA-512",
        _ => "unknown",
    }
}

pub fn verify_any_cms_signature(
    message: &[u8],
    signature_alg_oid: &str,
    signature_alg_params: Option<&[u8]>,
    digest_alg_oid: &str,
    signature: &[u8],
    cert_der: &[u8],
) -> bool {
    let Some(public_key) = public_key_from_cert(cert_der) else {
        return false;
    };
    let Some(digest) = digest(message, digest_alg_oid) else {
        return false;
    };
    match public_key {
        PublicKey::Rsa(key) => verify_rsa_signature(
            &key,
            signature_alg_oid,
            signature_alg_params,
            normalized_digest_oid(digest_alg_oid),
            &digest,
            signature,
        ),
        PublicKey::Ec { curve_oid, point } => {
            verify_ecdsa_signature(&curve_oid, signature_alg_oid, &digest, signature, &point)
        }
    }
}

pub fn normalized_digest_oid(oid: &str) -> &str {
    match oid {
        OID_RSA_SHA1 => OID_SHA1,
        OID_RSA_SHA256 | OID_ECDSA_SHA256 | OID_ECDSA_PLAIN_SHA256 => OID_SHA256,
        OID_RSA_SHA384 | OID_ECDSA_SHA384 | OID_ECDSA_PLAIN_SHA384 => OID_SHA384,
        OID_RSA_SHA512 | OID_ECDSA_SHA512 | OID_ECDSA_PLAIN_SHA512 => OID_SHA512,
        _ => oid,
    }
}

pub fn verify_signature_digest(
    signature_alg_oid: &str,
    signature_alg_params: Option<&[u8]>,
    digest_alg_oid: &str,
    digest: &[u8],
    signature: &[u8],
    cert_der: &[u8],
) -> bool {
    let Some(public_key) = public_key_from_cert(cert_der) else {
        return false;
    };
    match public_key {
        PublicKey::Rsa(key) => verify_rsa_signature(
            &key,
            signature_alg_oid,
            signature_alg_params,
            normalized_digest_oid(digest_alg_oid),
            digest,
            signature,
        ),
        PublicKey::Ec { curve_oid, point } => {
            verify_ecdsa_signature(&curve_oid, signature_alg_oid, digest, signature, &point)
        }
    }
}

pub fn signature_algorithm_matches_certificate_key(
    signature_alg_oid: &str,
    cert_der: &[u8],
) -> bool {
    let Some(public_key) = public_key_from_cert(cert_der) else {
        return false;
    };
    match public_key {
        PublicKey::Rsa(_) => !is_ec_signature_algorithm(signature_alg_oid),
        PublicKey::Ec { .. } => !is_rsa_signature_algorithm(signature_alg_oid),
    }
}

enum PublicKey {
    Rsa(RsaPublicParts),
    Ec { curve_oid: String, point: Vec<u8> },
}

fn is_rsa_signature_algorithm(oid: &str) -> bool {
    matches!(
        oid,
        OID_RSA_ENCRYPTION
            | OID_RSA_PSS
            | OID_RSA_SHA1
            | OID_RSA_SHA256
            | OID_RSA_SHA384
            | OID_RSA_SHA512
    )
}

fn is_ec_signature_algorithm(oid: &str) -> bool {
    matches!(
        oid,
        OID_ECDSA_SHA1
            | OID_ECDSA_SHA256
            | OID_ECDSA_SHA384
            | OID_ECDSA_SHA512
            | OID_ECDSA_PLAIN_SHA256
            | OID_ECDSA_PLAIN_SHA384
            | OID_ECDSA_PLAIN_SHA512
    )
}

struct RsaPublicParts {
    n: BigUint,
    e: BigUint,
}

fn public_key_from_cert(cert_der: &[u8]) -> Option<PublicKey> {
    let mut cert_reader = asn1::Reader::new(cert_der);
    let cert = cert_reader.read_tlv()?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut body = asn1::Reader::new(&cert.content);
    let tbs = body.read_tlv()?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut tbs_body = asn1::Reader::new(&tbs.content);
    if tbs_body.peek_tag() == Some(0xa0) {
        let _ = tbs_body.read_tlv();
    }
    for _ in 0..5 {
        if !tbs_body.skip_one_tlv() {
            return None;
        }
    }
    let spki = tbs_body.read_tlv()?;
    parse_subject_public_key_info(&spki.content)
}

fn parse_subject_public_key_info(spki: &[u8]) -> Option<PublicKey> {
    let mut reader = asn1::Reader::new(spki);
    let alg = reader.read_tlv()?;
    if alg.tag != 0x30 {
        return None;
    }
    let mut alg_reader = asn1::Reader::new(&alg.content);
    let alg_oid_tlv = alg_reader.read_tlv()?;
    if alg_oid_tlv.tag != 0x06 {
        return None;
    }
    let alg_oid = asn1::oid_string(&alg_oid_tlv.content);
    let params = alg_reader.read_tlv();
    let bit_string = reader.read_tlv()?;
    if bit_string.tag != 0x03 || bit_string.content.is_empty() {
        return None;
    }
    let key_bytes = &bit_string.content[1..];
    if alg_oid == OID_RSA_ENCRYPTION {
        parse_rsa_public_key(key_bytes).map(PublicKey::Rsa)
    } else if alg_oid == OID_EC_PUBLIC_KEY {
        let curve_oid = params
            .filter(|tlv| tlv.tag == 0x06)
            .map(|tlv| asn1::oid_string(&tlv.content))?;
        Some(PublicKey::Ec {
            curve_oid,
            point: key_bytes.to_vec(),
        })
    } else {
        None
    }
}

fn parse_rsa_public_key(key_der: &[u8]) -> Option<RsaPublicParts> {
    let mut reader = asn1::Reader::new(key_der);
    let seq = reader.read_tlv()?;
    if seq.tag != 0x30 {
        return None;
    }
    let mut body = asn1::Reader::new(&seq.content);
    let modulus = body.read_tlv()?;
    let exponent = body.read_tlv()?;
    if modulus.tag != 0x02 || exponent.tag != 0x02 {
        return None;
    }
    Some(RsaPublicParts {
        n: BigUint::from_bytes_be(&unsigned_integer_bytes(&modulus.content)),
        e: BigUint::from_bytes_be(&unsigned_integer_bytes(&exponent.content)),
    })
}

fn verify_rsa_signature(
    key: &RsaPublicParts,
    signature_alg_oid: &str,
    signature_alg_params: Option<&[u8]>,
    digest_oid: &str,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    match (signature_alg_oid, digest_oid) {
        (OID_RSA_PSS, _) => verify_rsa_pss_signature(
            key,
            signature_alg_params,
            digest_oid,
            digest,
            signature,
        ),
        (OID_RSA_SHA1, _) | (OID_RSA_ENCRYPTION, OID_SHA1) => {
            verify_rsa_pkcs1_digest_info(key, OID_SHA1, digest, signature)
        }
        (OID_RSA_SHA384, _) | (OID_RSA_ENCRYPTION, OID_SHA384) => {
            verify_rsa_pkcs1_digest_info(key, OID_SHA384, digest, signature)
        }
        (OID_RSA_SHA512, _) | (OID_RSA_ENCRYPTION, OID_SHA512) => {
            verify_rsa_pkcs1_digest_info(key, OID_SHA512, digest, signature)
        }
        (OID_RSA_SHA256, _) | (OID_RSA_ENCRYPTION, _) => {
            verify_rsa_pkcs1_digest_info(key, OID_SHA256, digest, signature)
        }
        _ => false,
    }
}

fn verify_rsa_pss_signature(
    key: &RsaPublicParts,
    signature_alg_params: Option<&[u8]>,
    digest_oid: &str,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let Some(params) = rsa_pss_params(signature_alg_params) else {
        return false;
    };
    if params.hash_oid != digest_oid
        || params.mgf1_hash_oid != params.hash_oid
        || params.trailer_field != 1
    {
        return false;
    }
    let Some(rsa_key) = rsa_public_key(key) else {
        return false;
    };
    let Ok(sig) = pss::Signature::try_from(signature) else {
        return false;
    };
    match params.hash_oid.as_str() {
        OID_SHA1 => pss::VerifyingKey::<Sha1>::new_with_salt_len(rsa_key, params.salt_len)
            .verify_prehash(digest, &sig)
            .is_ok(),
        OID_SHA256 => pss::VerifyingKey::<Sha256>::new_with_salt_len(rsa_key, params.salt_len)
            .verify_prehash(digest, &sig)
            .is_ok(),
        OID_SHA384 => pss::VerifyingKey::<Sha384>::new_with_salt_len(rsa_key, params.salt_len)
            .verify_prehash(digest, &sig)
            .is_ok(),
        OID_SHA512 => pss::VerifyingKey::<Sha512>::new_with_salt_len(rsa_key, params.salt_len)
            .verify_prehash(digest, &sig)
            .is_ok(),
        _ => false,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RsaPssParams {
    hash_oid: String,
    mgf1_hash_oid: String,
    salt_len: usize,
    trailer_field: usize,
}

fn rsa_pss_params(params_der: Option<&[u8]>) -> Option<RsaPssParams> {
    let mut params = RsaPssParams {
        hash_oid: OID_SHA1.to_owned(),
        mgf1_hash_oid: OID_SHA1.to_owned(),
        salt_len: 20,
        trailer_field: 1,
    };
    let Some(params_der) = params_der else {
        return Some(params);
    };
    let mut reader = asn1::Reader::new(params_der);
    let sequence = reader.read_tlv()?;
    if sequence.tag != 0x30 {
        return None;
    }
    let mut fields = asn1::Reader::new(&sequence.content);
    while let Some(field) = fields.read_tlv() {
        match field.tag {
            0xa0 => params.hash_oid = parse_hash_algorithm_identifier(&field.content)?,
            0xa1 => {
                let (mgf_oid, mgf_hash_oid) = parse_mgf1_algorithm_identifier(&field.content)?;
                if mgf_oid != OID_MGF1 {
                    return None;
                }
                params.mgf1_hash_oid = mgf_hash_oid;
            }
            0xa2 => params.salt_len = parse_explicit_integer(&field.content)?,
            0xa3 => params.trailer_field = parse_explicit_integer(&field.content)?,
            _ => return None,
        }
    }
    Some(params)
}

fn parse_hash_algorithm_identifier(der: &[u8]) -> Option<String> {
    let mut reader = asn1::Reader::new(der);
    let alg = reader.read_tlv()?;
    if alg.tag != 0x30 {
        return None;
    }
    cms::algorithm_identifier_oid(&alg.content)
}

fn parse_mgf1_algorithm_identifier(der: &[u8]) -> Option<(String, String)> {
    let mut reader = asn1::Reader::new(der);
    let alg = reader.read_tlv()?;
    if alg.tag != 0x30 {
        return None;
    }
    let (mgf_oid, params) = cms::algorithm_identifier_oid_and_params(&alg.content)?;
    let mgf_hash_oid = parse_hash_algorithm_identifier(&params?)?;
    Some((mgf_oid, mgf_hash_oid))
}

fn parse_explicit_integer(der: &[u8]) -> Option<usize> {
    let mut reader = asn1::Reader::new(der);
    let int = reader.read_tlv()?;
    if int.tag != 0x02 {
        return None;
    }
    Some(asn1::int_value(&int.content))
}

fn rsa_public_key(key: &RsaPublicParts) -> Option<RsaPublicKey> {
    RsaPublicKey::new(key.n.clone(), key.e.clone()).ok()
}

fn verify_rsa_pkcs1_digest_info(
    key: &RsaPublicParts,
    digest_oid: &str,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let k = key.n.bits().div_ceil(8);
    if signature.len() != k {
        return false;
    }

    let m = BigUint::from_bytes_be(signature).modpow(&key.e, &key.n);
    let mut encoded = m.to_bytes_be();
    if encoded.len() > k {
        return false;
    }
    if encoded.len() < k {
        let mut padded = vec![0; k - encoded.len()];
        padded.extend(encoded);
        encoded = padded;
    }

    let Some(prefix) = digest_info_prefix(digest_oid) else {
        return false;
    };
    let t_len = prefix.len() + digest.len();
    if encoded.len() < t_len + 11 {
        return false;
    }

    let padding_end = encoded.len() - t_len - 1;
    let ok = encoded.first() == Some(&0x00)
        && encoded.get(1) == Some(&0x01)
        && padding_end >= 10
        && encoded[2..padding_end].iter().all(|b| *b == 0xff)
        && encoded[padding_end] == 0x00
        && encoded[padding_end + 1..padding_end + 1 + prefix.len()] == *prefix
        && encoded[padding_end + 1 + prefix.len()..] == *digest;
    ok
}

fn digest_info_prefix(digest_oid: &str) -> Option<&'static [u8]> {
    match digest_oid {
        OID_SHA1 => Some(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]),
        OID_SHA256 => Some(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        OID_SHA384 => Some(&[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]),
        OID_SHA512 => Some(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        _ => None,
    }
}

fn verify_ecdsa_signature(
    curve_oid: &str,
    signature_alg_oid: &str,
    digest: &[u8],
    signature: &[u8],
    point: &[u8],
) -> bool {
    if !matches!(
        signature_alg_oid,
        OID_ECDSA_SHA256
            | OID_ECDSA_SHA384
            | OID_ECDSA_SHA512
            | OID_ECDSA_PLAIN_SHA256
            | OID_ECDSA_PLAIN_SHA384
            | OID_ECDSA_PLAIN_SHA512
    ) {
        return false;
    }
    let der_signature = if matches!(
        signature_alg_oid,
        OID_ECDSA_PLAIN_SHA256 | OID_ECDSA_PLAIN_SHA384 | OID_ECDSA_PLAIN_SHA512
    ) {
        der_encoded_plain_ecdsa_signature(signature)
    } else {
        Some(signature.to_vec())
    };
    let Some(der_signature) = der_signature else {
        return false;
    };
    match curve_oid {
        OID_PRIME256V1 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let Ok(sig) = p256::ecdsa::Signature::from_der(&der_signature) else {
                return false;
            };
            key.verify_prehash(digest, &sig).is_ok()
        }
        OID_SECP384R1 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
            let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let Ok(sig) = p384::ecdsa::Signature::from_der(&der_signature) else {
                return false;
            };
            key.verify_prehash(digest, &sig).is_ok()
        }
        OID_BRAINPOOL_P256R1 => {
            use ecdsa17::signature::hazmat::PrehashVerifier as _;
            let Ok(key) = ecdsa17::VerifyingKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(point)
            else {
                return false;
            };
            let Ok(sig) = bp256::r1::ecdsa::DerSignature::from_bytes(&der_signature) else {
                return false;
            };
            key.verify_prehash(digest, &sig).is_ok()
        }
        _ => false,
    }
}

fn der_encoded_plain_ecdsa_signature(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 2 || !raw.len().is_multiple_of(2) {
        return None;
    }
    let half = raw.len() / 2;
    let mut body = der_encoded_integer(&raw[..half]);
    body.extend(der_encoded_integer(&raw[half..]));
    let mut out = vec![0x30];
    out.extend(asn1::der_length(body.len()));
    out.extend(body);
    Some(out)
}

fn der_encoded_integer(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes.to_vec();
    while value.len() > 1 && value[0] == 0 && (value[1] & 0x80) == 0 {
        value.remove(0);
    }
    if value.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        value.insert(0, 0);
    }
    let mut out = vec![0x02];
    out.extend(asn1::der_length(value.len()));
    out.extend(value);
    out
}

fn unsigned_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.len() > 1 && out.first() == Some(&0) {
        out.remove(0);
    }
    out
}

#[allow(dead_code)]
pub fn signer_digest_from_alg_identifier(alg_id: &[u8]) -> Option<String> {
    cms::algorithm_identifier_oid(alg_id).map(|oid| normalized_digest_oid(&oid).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_rsa_pss_parameters() {
        let params_der = [
            0x30, 0x39, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a,
            0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60,
            0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02,
            0x01, 0x20, 0xa3, 0x03, 0x02, 0x01, 0x01,
        ];

        assert_eq!(
            rsa_pss_params(Some(&params_der)),
            Some(RsaPssParams {
                hash_oid: OID_SHA256.to_owned(),
                mgf1_hash_oid: OID_SHA256.to_owned(),
                salt_len: 32,
                trailer_field: 1,
            })
        );
    }

    #[test]
    fn rsa_pss_parameters_default_to_sha1_profile() {
        assert_eq!(
            rsa_pss_params(None),
            Some(RsaPssParams {
                hash_oid: OID_SHA1.to_owned(),
                mgf1_hash_oid: OID_SHA1.to_owned(),
                salt_len: 20,
                trailer_field: 1,
            })
        );
    }
}
