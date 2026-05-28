use crate::{asn1, crypto};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const APPLE_REFERENCE_UNIX_OFFSET: f64 = 978_307_200.0;
const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const CEI_FALLBACK_CRL_URL: &str = "https://crl.cei.mai.gov.ro/crl/ro_cei_mai_sub-ca.crl";

#[derive(Clone, Debug, Default)]
pub struct RevocationOptions {
    pub crl_cache: CrlCache,
    pub now_unix_seconds: f64,
}

#[derive(Clone, Debug, Default)]
pub struct CrlCache {
    pub entries: Vec<CrlCacheEntry>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CrlCacheEntry {
    #[serde(skip)]
    pub cache_key_sha256: String,
    #[serde(rename = "validUntil")]
    pub valid_until: f64,
    #[serde(deserialize_with = "deserialize_base64_der")]
    pub der: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RevocationStatus {
    Good,
    Revoked { revoked_at: Option<f64> },
    Unavailable(String),
}

struct ParsedCrl {
    tbs: Vec<u8>,
    issuer: Vec<u8>,
    signature_alg_oid: String,
    signature_alg_params: Option<Vec<u8>>,
    signature: Vec<u8>,
    next_update: Option<f64>,
    revoked_entries: Vec<RevokedEntry>,
}

struct RevokedEntry {
    serial: Vec<u8>,
    revocation_date: Option<f64>,
}

impl CrlCache {
    pub fn from_directory(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let data = fs::read(&path)?;
            let mut cache_entry = Self::entry_from_json_slice(&data)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            cache_entry.cache_key_sha256 = stem.to_ascii_lowercase();
            entries.push(cache_entry);
        }
        entries.sort_by(|a, b| a.cache_key_sha256.cmp(&b.cache_key_sha256));
        Ok(Self { entries })
    }

    pub fn entry_from_json_slice(data: &[u8]) -> Result<CrlCacheEntry, serde_json::Error> {
        serde_json::from_slice(data)
    }

    fn data_for_url(&self, url: &str, now_unix_seconds: f64) -> Option<&[u8]> {
        let key = crl_cache_key(url);
        let now_apple_seconds = unix_time_to_apple_reference_time(now_unix_seconds);
        self.entries
            .iter()
            .find(|entry| entry.cache_key_sha256 == key && entry.valid_until > now_apple_seconds)
            .map(|entry| entry.der.as_slice())
    }
}

pub fn check_certificate_status(
    cert_der: &[u8],
    issuer_certificates: &[Vec<u8>],
    now_unix_seconds: f64,
    cache: &CrlCache,
) -> RevocationStatus {
    let Some(serial) = certificate_serial(cert_der) else {
        return RevocationStatus::Unavailable(
            "Couldn't read the signing certificate serial number.".to_owned(),
        );
    };

    let urls = crl_urls(cert_der);
    if urls.is_empty() {
        return RevocationStatus::Unavailable(
            "Couldn't find a revocation list for the signing certificate.".to_owned(),
        );
    }

    let mut last_failure = None;
    for url in urls {
        let Some(crl_der) = cache.data_for_url(&url, now_unix_seconds) else {
            last_failure = Some(
                "Couldn't check the signing certificate revocation list. Check your internet connection and try again."
                    .to_owned(),
            );
            continue;
        };
        let Some(crl) = parse_crl(crl_der) else {
            last_failure =
                Some("The signing certificate revocation list couldn't be read.".to_owned());
            continue;
        };
        if !authenticate_crl(&crl, cert_der, issuer_certificates) {
            last_failure = Some(
                "The signing certificate revocation list couldn't be authenticated.".to_owned(),
            );
            continue;
        }
        if crl
            .next_update
            .is_some_and(|next_update| next_update <= now_unix_seconds)
        {
            last_failure = Some("The signing certificate revocation list is expired.".to_owned());
            continue;
        }
        if let Some(entry) = crl
            .revoked_entries
            .iter()
            .find(|entry| entry.serial == serial)
        {
            return RevocationStatus::Revoked {
                revoked_at: entry.revocation_date,
            };
        }
        return RevocationStatus::Good;
    }

    RevocationStatus::Unavailable(last_failure.unwrap_or_else(|| {
        "Couldn't find a revocation list for the signing certificate.".to_owned()
    }))
}

pub fn asn1_time_to_unix_seconds(raw: &str) -> Option<f64> {
    let digit_count = asn1_time_digit_count(raw);
    let year_digits = match digit_count {
        10 | 12 => 2,
        14 => 4,
        _ => return None,
    };
    parse_asn1_time(raw, year_digits)
}

pub fn claimed_time_to_unix_seconds(raw: &str) -> Option<f64> {
    asn1_time_to_unix_seconds(raw).or_else(|| pdf_date_to_unix_seconds(raw))
}

fn pdf_date_to_unix_seconds(raw: &str) -> Option<f64> {
    let value = raw.strip_prefix("D:").unwrap_or(raw);
    let digit_len = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_len < 4 {
        return None;
    }
    let digits = &value[..digit_len];
    let component = |start: usize, length: usize, default_value: u32| -> Option<u32> {
        if start >= digits.len() {
            return Some(default_value);
        }
        let end = usize::min(start + length, digits.len());
        digits[start..end].parse().ok()
    };
    let year: i32 = component(0, 4, 1970)?.try_into().ok()?;
    let month = component(4, 2, 1)?;
    let day = component(6, 2, 1)?;
    let hour = component(8, 2, 0)?;
    let minute = component(10, 2, 0)?;
    let second = component(12, 2, 0)?;
    let suffix = &value[digit_len..];
    let offset_seconds = match suffix.as_bytes().first().copied() {
        Some(sign @ (b'+' | b'-')) => {
            let zone_digits: String = suffix[1..]
                .bytes()
                .filter(u8::is_ascii_digit)
                .map(char::from)
                .collect();
            let hours: i64 = zone_digits
                .get(..usize::min(2, zone_digits.len()))
                .unwrap_or("")
                .parse()
                .unwrap_or(0);
            let minutes: i64 = zone_digits
                .get(2..usize::min(4, zone_digits.len()))
                .unwrap_or("")
                .parse()
                .unwrap_or(0);
            (hours * 3600 + minutes * 60) * if sign == b'+' { 1 } else { -1 }
        }
        _ => 0,
    };
    Some(
        unix_seconds_from_ymdhms(year, month, day, hour, minute, second)? as f64
            - offset_seconds as f64,
    )
}

fn asn1_time_digit_count(raw: &str) -> usize {
    let without_zone = raw
        .trim_end_matches('Z')
        .rsplit_once(['+', '-'])
        .map(|(value, _)| value)
        .unwrap_or(raw.trim_end_matches('Z'));
    without_zone
        .split('.')
        .next()
        .unwrap_or_default()
        .bytes()
        .filter(u8::is_ascii_digit)
        .count()
}

fn crl_urls(cert_der: &[u8]) -> Vec<String> {
    let mut urls = Vec::new();
    for url in crl_distribution_point_urls(cert_der) {
        let Some(normalized) = normalize_crl_url(&url) else {
            continue;
        };
        if !urls.contains(&normalized) {
            urls.push(normalized);
        }
    }
    if urls.is_empty() && is_cei_issued_certificate(cert_der) {
        urls.push(CEI_FALLBACK_CRL_URL.to_owned());
    }
    urls
}

fn crl_distribution_point_urls(cert_der: &[u8]) -> Vec<String> {
    let Some(extensions) = certificate_extensions(cert_der) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for ext in extensions {
        let mut ext_reader = asn1::Reader::new(&ext);
        let Some(oid_tlv) = ext_reader.read_tlv() else {
            continue;
        };
        if oid_tlv.tag != 0x06 || asn1::oid_string(&oid_tlv.content) != OID_CRL_DISTRIBUTION_POINTS
        {
            continue;
        }
        if ext_reader.peek_tag() == Some(0x01) {
            let _ = ext_reader.read_tlv();
        }
        let Some(value) = ext_reader.read_tlv() else {
            continue;
        };
        if value.tag == 0x04 {
            scan_for_uri(&value.content, &mut urls);
        }
    }
    urls
}

fn normalize_crl_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("https://") {
        &url[8..]
    } else {
        return None;
    };
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some(format!("https://{rest}"))
}

pub(crate) fn crl_cache_key_for_url(url: &str) -> Option<String> {
    normalize_crl_url(url).map(|url| crl_cache_key(&url))
}

fn crl_cache_key(url: &str) -> String {
    hex::encode(Sha256::digest(url.as_bytes()))
}

fn parse_crl(der: &[u8]) -> Option<ParsedCrl> {
    let mut reader = asn1::Reader::new(der);
    let cert_list = reader.read_tlv()?;
    if cert_list.tag != 0x30 {
        return None;
    }
    let mut cert_list_reader = asn1::Reader::new(&cert_list.content);
    let tbs = cert_list_reader.read_tlv()?;
    let signature_algorithm = cert_list_reader.read_tlv()?;
    let signature_value = cert_list_reader.read_tlv()?;
    if tbs.tag != 0x30
        || signature_algorithm.tag != 0x30
        || signature_value.tag != 0x03
        || signature_value.content.first() != Some(&0)
    {
        return None;
    }
    let (signature_alg_oid, signature_alg_params) =
        crate::cms::algorithm_identifier_oid_and_params(&signature_algorithm.content)?;

    let mut tbs_reader = asn1::Reader::new(&tbs.content);
    if tbs_reader.peek_tag() == Some(0x02) {
        let _ = tbs_reader.read_tlv();
    }
    tbs_reader.skip_one_tlv();
    let issuer = tbs_reader.read_tlv()?;
    tbs_reader.skip_one_tlv();
    if issuer.tag != 0x30 {
        return None;
    }
    let next_update = if matches!(tbs_reader.peek_tag(), Some(0x17 | 0x18)) {
        let next = tbs_reader.read_tlv()?;
        time_tlv_to_unix_seconds(&next)
    } else {
        None
    };

    let mut revoked_entries = Vec::new();
    if tbs_reader.peek_tag() == Some(0x30) {
        let revoked = tbs_reader.read_tlv()?;
        let mut revoked_reader = asn1::Reader::new(&revoked.content);
        while let Some(entry) = revoked_reader.read_tlv() {
            if entry.tag != 0x30 {
                continue;
            }
            let mut entry_reader = asn1::Reader::new(&entry.content);
            let Some(serial) = entry_reader.read_tlv() else {
                continue;
            };
            if serial.tag != 0x02 {
                continue;
            }
            let revocation_date = entry_reader
                .read_tlv()
                .as_ref()
                .and_then(time_tlv_to_unix_seconds);
            revoked_entries.push(RevokedEntry {
                serial: normalize_serial(&serial.content),
                revocation_date,
            });
        }
    }

    Some(ParsedCrl {
        tbs: tbs.full_bytes,
        issuer: issuer.full_bytes,
        signature_alg_oid,
        signature_alg_params,
        signature: signature_value.content[1..].to_vec(),
        next_update,
        revoked_entries,
    })
}

fn authenticate_crl(crl: &ParsedCrl, cert_der: &[u8], issuer_certificates: &[Vec<u8>]) -> bool {
    let Some(certificate_issuer) = certificate_issuer(cert_der) else {
        return false;
    };
    let mut candidates = vec![cert_der.to_vec()];
    candidates.extend(issuer_certificates.iter().cloned());
    candidates = unique_bytes(candidates);
    for issuer_der in candidates {
        let Some(issuer_subject) = certificate_subject(&issuer_der) else {
            continue;
        };
        if issuer_subject != certificate_issuer || issuer_subject != crl.issuer {
            continue;
        }
        let digest_oid = crypto::normalized_digest_oid(&crl.signature_alg_oid);
        let Some(digest) = crypto::digest(&crl.tbs, digest_oid) else {
            continue;
        };
        if crypto::verify_signature_digest(
            &crl.signature_alg_oid,
            crl.signature_alg_params.as_deref(),
            digest_oid,
            &digest,
            &crl.signature,
            &issuer_der,
        ) {
            return true;
        }
    }
    false
}

fn certificate_serial(der: &[u8]) -> Option<Vec<u8>> {
    let tbs = certificate_tbs(der)?;
    let mut reader = asn1::Reader::new(&tbs.content);
    if reader.peek_tag() == Some(0xa0) {
        let _ = reader.read_tlv();
    }
    let serial = reader.read_tlv()?;
    if serial.tag == 0x02 {
        Some(normalize_serial(&serial.content))
    } else {
        None
    }
}

fn certificate_issuer(der: &[u8]) -> Option<Vec<u8>> {
    let tbs = certificate_tbs(der)?;
    let mut reader = asn1::Reader::new(&tbs.content);
    if reader.peek_tag() == Some(0xa0) {
        let _ = reader.read_tlv();
    }
    reader.skip_one_tlv();
    reader.skip_one_tlv();
    let issuer = reader.read_tlv()?;
    if issuer.tag == 0x30 {
        Some(issuer.full_bytes)
    } else {
        None
    }
}

fn certificate_subject(der: &[u8]) -> Option<Vec<u8>> {
    let tbs = certificate_tbs(der)?;
    let mut reader = asn1::Reader::new(&tbs.content);
    if reader.peek_tag() == Some(0xa0) {
        let _ = reader.read_tlv();
    }
    reader.skip_one_tlv();
    reader.skip_one_tlv();
    reader.skip_one_tlv();
    reader.skip_one_tlv();
    let subject = reader.read_tlv()?;
    if subject.tag == 0x30 {
        Some(subject.full_bytes)
    } else {
        None
    }
}

fn certificate_extensions(der: &[u8]) -> Option<Vec<Vec<u8>>> {
    let tbs = certificate_tbs(der)?;
    let mut reader = asn1::Reader::new(&tbs.content);
    if reader.peek_tag() == Some(0xa0) {
        let _ = reader.read_tlv();
    }
    for _ in 0..6 {
        reader.skip_one_tlv();
    }
    while let Some(field) = reader.read_tlv() {
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

fn certificate_tbs(der: &[u8]) -> Option<asn1::Tlv> {
    let mut reader = asn1::Reader::new(der);
    let cert = reader.read_tlv()?;
    if cert.tag != 0x30 {
        return None;
    }
    let mut cert_reader = asn1::Reader::new(&cert.content);
    let tbs = cert_reader.read_tlv()?;
    if tbs.tag == 0x30 {
        Some(tbs)
    } else {
        None
    }
}

fn is_cei_issued_certificate(der: &[u8]) -> bool {
    let Some(issuer) = certificate_issuer(der) else {
        return false;
    };
    strings_in_der(&issuer).iter().any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("ro cei mai sub-ca")
            || value.contains("ro cei mai root-ca")
            || value.contains("ministerul afacerilor interne")
    })
}

fn scan_for_uri(data: &[u8], urls: &mut Vec<String>) {
    let mut reader = asn1::Reader::new(data);
    while let Some(tlv) = reader.read_tlv() {
        if tlv.tag == 0x86 {
            if let Ok(url) = String::from_utf8(tlv.content.clone()) {
                urls.push(url);
            }
        }
        if tlv.tag & 0x20 != 0 || tlv.tag == 0x04 {
            scan_for_uri(&tlv.content, urls);
        }
    }
}

fn strings_in_der(data: &[u8]) -> Vec<String> {
    let mut reader = asn1::Reader::new(data);
    let mut out = Vec::new();
    while let Some(tlv) = reader.read_tlv() {
        match tlv.tag {
            0x0c | 0x13 | 0x16 | 0x14 => {
                if let Ok(value) = String::from_utf8(tlv.content.clone()) {
                    out.push(value);
                }
            }
            0x1e => {
                if let Some(value) = bmp_string(&tlv.content) {
                    out.push(value);
                }
            }
            _ => {}
        }
        if tlv.tag & 0x20 != 0 {
            out.extend(strings_in_der(&tlv.content));
        }
    }
    out
}

fn bmp_string(data: &[u8]) -> Option<String> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let mut out = String::new();
    for chunk in data.chunks(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        out.push(char::from_u32(u32::from(value))?);
    }
    Some(out)
}

fn time_tlv_to_unix_seconds(tlv: &asn1::Tlv) -> Option<f64> {
    let raw = String::from_utf8(tlv.content.clone()).ok()?;
    let year_digits = match tlv.tag {
        0x17 => 2,
        0x18 => 4,
        _ => return None,
    };
    parse_asn1_time(&raw, year_digits)
}

fn parse_asn1_time(raw: &str, year_digits: usize) -> Option<f64> {
    let mut value = raw.trim_end_matches('Z').to_owned();
    let mut offset_seconds = 0i64;
    if value.len() > 5 {
        let sign_index = value.len() - 5;
        let sign = value.as_bytes()[sign_index];
        if sign == b'+' || sign == b'-' {
            let zone = &value[sign_index + 1..];
            if zone.len() == 4 {
                let hours: i64 = zone[0..2].parse().ok()?;
                let minutes: i64 = zone[2..4].parse().ok()?;
                offset_seconds = (hours * 3600 + minutes * 60) * if sign == b'+' { 1 } else { -1 };
                value.truncate(sign_index);
            }
        }
    }
    let digits = value.split('.').next().unwrap_or_default();
    let min_len = year_digits + 8;
    if digits.len() != min_len && digits.len() != min_len + 2 {
        return None;
    }
    let mut year: i32 = digits[0..year_digits].parse().ok()?;
    if year_digits == 2 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let month: u32 = digits[year_digits..year_digits + 2].parse().ok()?;
    let day: u32 = digits[year_digits + 2..year_digits + 4].parse().ok()?;
    let hour: u32 = digits[year_digits + 4..year_digits + 6].parse().ok()?;
    let minute: u32 = digits[year_digits + 6..year_digits + 8].parse().ok()?;
    let second: u32 = if digits.len() >= min_len + 2 {
        digits[year_digits + 8..year_digits + 10].parse().ok()?
    } else {
        0
    };
    Some(
        unix_seconds_from_ymdhms(year, month, day, hour, minute, second)? as f64
            - offset_seconds as f64,
    )
}

fn unix_seconds_from_ymdhms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + i64::from(hour * 3600 + minute * 60 + second))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    i64::from(era) * 146_097 + i64::from(doe) - 719_468
}

fn unix_time_to_apple_reference_time(unix_seconds: f64) -> f64 {
    unix_seconds - APPLE_REFERENCE_UNIX_OFFSET
}

fn normalize_serial(data: &[u8]) -> Vec<u8> {
    let mut bytes = data.to_vec();
    while bytes.len() > 1 && bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    bytes
}

fn unique_bytes(bytes: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for item in bytes {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn deserialize_base64_der<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::{asn1_time_to_unix_seconds, claimed_time_to_unix_seconds};

    #[test]
    fn parses_utc_and_generalized_asn1_times() {
        assert_eq!(
            asn1_time_to_unix_seconds("260525000000Z"),
            Some(1_779_667_200.0)
        );
        assert_eq!(
            asn1_time_to_unix_seconds("20260525000000Z"),
            Some(1_779_667_200.0)
        );
    }

    #[test]
    fn parses_pdf_dates_used_as_claimed_signing_times() {
        assert_eq!(
            claimed_time_to_unix_seconds("D:20171201225827+02'00'"),
            Some(1_512_161_907.0)
        );
        assert_eq!(
            claimed_time_to_unix_seconds("20171201205827Z"),
            Some(1_512_161_907.0)
        );
        assert_eq!(
            claimed_time_to_unix_seconds("D:201712"),
            Some(1_512_086_400.0)
        );
    }
}
