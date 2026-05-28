#[derive(Clone, Debug, Default)]
pub struct VerificationOptions {
    pub signer_trust_anchors: Vec<Vec<u8>>,
    pub signer_trust_anchor_sets: Vec<TimedTrustAnchorSet>,
    pub timestamp_trust_anchors: Vec<Vec<u8>>,
    pub timestamp_trust_anchor_sets: Vec<TimedTrustAnchorSet>,
    pub timestamp_certificate_sha256_pins: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TimedTrustAnchorSet {
    pub valid_from_unix_seconds: Option<f64>,
    pub valid_until_unix_seconds: Option<f64>,
    pub anchors: Vec<Vec<u8>>,
}
