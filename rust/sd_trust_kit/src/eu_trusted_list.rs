use base64::Engine;
use serde::Deserialize;

use crate::TimedTrustAnchorSet;

const APPLE_REFERENCE_UNIX_OFFSET: f64 = 978_307_200.0;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EuTrustedListCache {
    #[serde(rename = "fetchedAt")]
    pub fetched_at: f64,
    pub entries: Vec<EuTrustedCertificate>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EuTrustedCertificate {
    #[serde(deserialize_with = "deserialize_base64_der")]
    pub der: Vec<u8>,
    pub territory: String,
    #[serde(rename = "serviceName")]
    pub service_name: Option<String>,
    #[serde(rename = "serviceType")]
    pub service_type: String,
    pub status: String,
    #[serde(rename = "validFrom")]
    pub valid_from: Option<f64>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<f64>,
}

impl EuTrustedListCache {
    pub fn from_json_slice(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    pub fn fetched_at_unix_time(&self) -> f64 {
        apple_reference_time_to_unix_time(self.fetched_at)
    }

    pub fn trusted_signer_anchors_at_unix_time(&self, unix_seconds: f64) -> Vec<Vec<u8>> {
        self.trusted_signer_anchors_at_apple_reference_time(unix_time_to_apple_reference_time(
            unix_seconds,
        ))
    }

    pub fn trusted_timestamp_anchors_at_unix_time(&self, unix_seconds: f64) -> Vec<Vec<u8>> {
        self.trusted_timestamp_anchors_at_apple_reference_time(unix_time_to_apple_reference_time(
            unix_seconds,
        ))
    }

    pub fn signer_trust_anchor_sets(&self) -> Vec<TimedTrustAnchorSet> {
        self.entries
            .iter()
            .filter(|entry| {
                qualifies_status(&entry.status) && entry.is_qualified_certificate_service()
            })
            .map(timed_anchor_set)
            .collect()
    }

    pub fn timestamp_trust_anchor_sets(&self) -> Vec<TimedTrustAnchorSet> {
        self.entries
            .iter()
            .filter(|entry| {
                qualifies_status(&entry.status) && entry.is_qualified_timestamp_service()
            })
            .map(timed_anchor_set)
            .collect()
    }

    fn trusted_signer_anchors_at_apple_reference_time(&self, apple_seconds: f64) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.is_trusted_at_apple_reference_time(apple_seconds)
                    && entry.is_qualified_certificate_service()
            })
            .map(|entry| entry.der.clone())
            .collect()
    }

    fn trusted_timestamp_anchors_at_apple_reference_time(
        &self,
        apple_seconds: f64,
    ) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.is_trusted_at_apple_reference_time(apple_seconds)
                    && entry.is_qualified_timestamp_service()
            })
            .map(|entry| entry.der.clone())
            .collect()
    }
}

impl EuTrustedCertificate {
    pub fn is_trusted_at_unix_time(&self, unix_seconds: f64) -> bool {
        self.is_trusted_at_apple_reference_time(unix_time_to_apple_reference_time(unix_seconds))
    }

    pub fn is_qualified_certificate_service(&self) -> bool {
        self.service_type.ends_with("/CA/QC")
    }

    pub fn is_qualified_timestamp_service(&self) -> bool {
        self.service_type.ends_with("/TSA/QTST")
            || self.service_type.ends_with("/TSA/TSS-QC")
            || self.service_type.ends_with("/TSA/TSS-AdESQCandQES")
    }

    fn is_trusted_at_apple_reference_time(&self, apple_seconds: f64) -> bool {
        if self
            .valid_from
            .is_some_and(|valid_from| apple_seconds < valid_from)
        {
            return false;
        }
        if self
            .valid_until
            .is_some_and(|valid_until| apple_seconds >= valid_until)
        {
            return false;
        }
        qualifies_status(&self.status)
    }
}

fn qualifies_status(status: &str) -> bool {
    let lower = status.to_ascii_lowercase();
    lower.ends_with("/granted")
        || lower.ends_with("/accredited")
        || lower.ends_with("/recognisedatnationallevel")
        || lower.ends_with("/undersupervision")
}

fn timed_anchor_set(entry: &EuTrustedCertificate) -> TimedTrustAnchorSet {
    TimedTrustAnchorSet {
        valid_from_unix_seconds: entry.valid_from.map(apple_reference_time_to_unix_time),
        valid_until_unix_seconds: entry.valid_until.map(apple_reference_time_to_unix_time),
        anchors: vec![entry.der.clone()],
    }
}

fn unix_time_to_apple_reference_time(unix_seconds: f64) -> f64 {
    unix_seconds - APPLE_REFERENCE_UNIX_OFFSET
}

fn apple_reference_time_to_unix_time(apple_seconds: f64) -> f64 {
    apple_seconds + APPLE_REFERENCE_UNIX_OFFSET
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
    use super::EuTrustedListCache;

    const CACHE_JSON: &[u8] =
        include_bytes!("../tests/fixtures/eu_trusted_list/trusted-certificates-v2.json");

    #[test]
    fn decodes_swift_cache_snapshot() {
        let cache = EuTrustedListCache::from_json_slice(CACHE_JSON).expect("trusted-list cache");

        assert_eq!(cache.entries.len(), 7_737);
        assert_eq!(cache.entries[0].territory, "AT");
        assert_eq!(cache.entries[0].der.len(), 1_237);
    }

    #[test]
    fn filters_entries_like_swift_trust_store() {
        let cache = EuTrustedListCache::from_json_slice(CACHE_JSON).expect("trusted-list cache");
        let unix_time = 801_223_479.036_306 + super::APPLE_REFERENCE_UNIX_OFFSET;

        assert_eq!(
            cache.trusted_signer_anchors_at_unix_time(unix_time).len(),
            1_000
        );
        assert_eq!(
            cache
                .trusted_timestamp_anchors_at_unix_time(unix_time)
                .len(),
            1_161
        );
    }
}
