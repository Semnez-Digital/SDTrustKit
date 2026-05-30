use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Fail,
    Warn,
    Skip,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Error,
    Valid,
    Warning,
    Inconclusive,
    Invalid,
    #[serde(rename = "noSignatures")]
    NoSignatures,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ValidationIndication {
    #[serde(rename = "passed")]
    TotalPassed,
    #[serde(rename = "failed")]
    TotalFailed,
    #[serde(rename = "needsEvidence")]
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ValidationSubIndication {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "formatIssue")]
    FormatFailure,
    #[serde(rename = "documentModifiedAfterSigning")]
    DocumentModifiedAfterSigning,
    #[serde(rename = "documentHashMismatch")]
    HashFailure,
    #[serde(rename = "signatureCryptographyIssue")]
    SignatureCryptoFailure,
    #[serde(rename = "signingCertificateMissing")]
    SigningCertificateNotFound,
    #[serde(rename = "certificateChainIssue")]
    CertificateChainGeneralFailure,
    #[serde(rename = "revocationEvidenceUnavailable")]
    RevocationOutOfBoundsNoPoe,
    #[serde(rename = "certificateRevoked")]
    Revoked,
    #[serde(rename = "timestampEvidenceIssue")]
    TimestampGeneralFailure,
    #[serde(rename = "cryptographicConstraintIssue")]
    CryptographicConstraintsFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StepKind {
    ParsePDF,
    SignatureFieldResolution,
    ByteRangeCoverage,
    ByteRangeBounds,
    DocumentModifiedAfterSigning,
    CmsStructure,
    PadesBaselineRequirements,
    SignerInfoPresent,
    MessageDigestMatches,
    MessageDigestAttribute,
    SignerCertificatePresent,
    SignerCertificateValidity,
    SignerCertificateKeyUsage,
    SignerCertificateExtendedKeyUsage,
    SignatureVerifySignedAttributes,
    SignatureVerifyContent,
    SignerCertificateChain,
    TsaTimestamp,
    TsaMessageImprint,
    TsaSignatureVerify,
    TsaExtendedKeyUsage,
    TsaCertificateChain,
    DocumentTimestamp,
    RevocationSigner,
    Other,
}

impl StepKind {
    pub fn name(self) -> &'static str {
        match self {
            StepKind::ParsePDF => "Parse PDF",
            StepKind::SignatureFieldResolution => "Signature field resolution",
            StepKind::ByteRangeCoverage => "/ByteRange coverage",
            StepKind::ByteRangeBounds => "/ByteRange bounds",
            StepKind::DocumentModifiedAfterSigning => "Document modified after signing",
            StepKind::CmsStructure => "CMS structure",
            StepKind::PadesBaselineRequirements => "PAdES baseline requirements",
            StepKind::SignerInfoPresent => "SignerInfo present",
            StepKind::MessageDigestMatches => "messageDigest matches",
            StepKind::MessageDigestAttribute => "messageDigest attr",
            StepKind::SignerCertificatePresent => "Signer certificate present",
            StepKind::SignerCertificateValidity => "Signer certificate validity",
            StepKind::SignerCertificateKeyUsage => "Signer certificate key usage",
            StepKind::SignerCertificateExtendedKeyUsage => "Signer certificate EKU",
            StepKind::SignatureVerifySignedAttributes => "Signature verify (SignedAttrs)",
            StepKind::SignatureVerifyContent => "Signature verify (content)",
            StepKind::SignerCertificateChain => "Cert chain (signer)",
            StepKind::TsaTimestamp => "TSA timestamp",
            StepKind::TsaMessageImprint => "TSA messageImprint",
            StepKind::TsaSignatureVerify => "TSA signature verify",
            StepKind::TsaExtendedKeyUsage => "TSA EKU",
            StepKind::TsaCertificateChain => "TSA cert chain",
            StepKind::DocumentTimestamp => "Document timestamp",
            StepKind::RevocationSigner => "Revocation (signer)",
            StepKind::Other => "Verification step",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Step {
    pub kind: StepKind,
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Step {
    pub fn new(kind: StepKind, status: Status, detail: impl Into<String>) -> Self {
        Self {
            kind,
            name: kind.name().to_owned(),
            status,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StandardsValidationResult {
    pub indication: ValidationIndication,
    #[serde(rename = "subIndication")]
    pub sub_indication: ValidationSubIndication,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CertificateDetails {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub der: Vec<u8>,
    #[serde(rename = "subjectSummary")]
    pub subject_summary: String,
    #[serde(rename = "issuerSummary")]
    pub issuer_summary: String,
    #[serde(rename = "commonName")]
    pub common_name: Option<String>,
    #[serde(rename = "serialNumberHex")]
    pub serial_number_hex: String,
    #[serde(rename = "sha1Fingerprint")]
    pub sha1_fingerprint: String,
    #[serde(rename = "sha256Fingerprint")]
    pub sha256_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimestampDetails {
    #[serde(rename = "timestampTime")]
    pub timestamp_time: Option<String>,
    #[serde(rename = "policyOID")]
    pub policy_oid: Option<String>,
    #[serde(rename = "serialNumberHex")]
    pub serial_number_hex: Option<String>,
    #[serde(rename = "messageImprintAlgorithm")]
    pub message_imprint_algorithm: Option<String>,
    #[serde(rename = "messageImprintHash")]
    pub message_imprint_hash: Option<String>,
    #[serde(rename = "tsaCertificate")]
    pub tsa_certificate: Option<CertificateDetails>,
    #[serde(rename = "tsaCertificateChain")]
    pub tsa_certificate_chain: Vec<CertificateDetails>,
    #[serde(rename = "trustDetail")]
    pub trust_detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PadesLevel {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "baselineB")]
    BaselineB,
    #[serde(rename = "baselineT")]
    BaselineT,
    #[serde(rename = "baselineLT")]
    BaselineLT,
    #[serde(rename = "baselineLTA")]
    BaselineLTA,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PreservationLevel {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "timestamped")]
    Timestamped,
    #[serde(rename = "longTerm")]
    LongTerm,
    #[serde(rename = "archival")]
    Archival,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreservationAssessment {
    pub level: PreservationLevel,
    pub label: String,
    pub detail: String,
}

impl PreservationAssessment {
    pub fn unknown(detail: impl Into<String>) -> Self {
        Self {
            level: PreservationLevel::Unknown,
            label: "Not assessed".to_owned(),
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureReport {
    pub index: usize,
    pub total: usize,
    #[serde(rename = "signedRevisionSize")]
    pub signed_revision_size: usize,
    #[serde(rename = "currentFileSize")]
    pub current_file_size: usize,
    #[serde(rename = "byteRange")]
    pub byte_range: Vec<usize>,
    pub steps: Vec<Step>,
    #[serde(rename = "signerName")]
    pub signer_name: Option<String>,
    #[serde(rename = "signingTime")]
    pub signing_time: Option<String>,
    #[serde(rename = "signerCertificate")]
    pub signer_certificate: Option<CertificateDetails>,
    #[serde(rename = "certificateChain")]
    pub certificate_chain: Vec<CertificateDetails>,
    #[serde(rename = "timestampDetails")]
    pub timestamp_details: Option<TimestampDetails>,
    pub verdict: Verdict,
    #[serde(rename = "padesLevel")]
    pub pades_level: PadesLevel,
    pub preservation: PreservationAssessment,
}

impl SignatureReport {
    pub fn standards(&self) -> StandardsValidationResult {
        standards_result_for(&self.steps)
    }

    pub fn refresh_preservation(&mut self) {
        let is_pades_baseline = self.pades_level != PadesLevel::Unknown;
        self.pades_level = pades_level_for_signature_steps(&self.steps, is_pades_baseline);
        self.preservation = preservation_assessment_for_level(self.pades_level);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationReport {
    pub steps: Vec<Step>,
    #[serde(rename = "signerName")]
    pub signer_name: Option<String>,
    #[serde(rename = "signerNames")]
    pub signer_names: Vec<String>,
    #[serde(rename = "signingTime")]
    pub signing_time: Option<String>,
    pub verdict: Verdict,
    pub signatures: Vec<SignatureReport>,
    #[serde(rename = "documentTimestamps")]
    pub document_timestamps: Vec<SignatureReport>,
    pub standards: StandardsValidationResult,
    #[serde(rename = "padesLevel")]
    pub pades_level: PadesLevel,
    pub preservation: PreservationAssessment,
}

impl ValidationReport {
    pub fn new(
        steps: Vec<Step>,
        signer_name: Option<String>,
        signer_names: Vec<String>,
        signing_time: Option<String>,
        verdict: Verdict,
    ) -> Self {
        let standards = standards_result_for(&steps);
        let preservation =
            PreservationAssessment::unknown("No PAdES document signature was assessed");
        Self {
            steps,
            signer_name,
            signer_names,
            signing_time,
            verdict,
            signatures: vec![],
            document_timestamps: vec![],
            standards,
            pades_level: PadesLevel::Unknown,
            preservation,
        }
    }
}

pub fn aggregate_report(
    signatures: Vec<SignatureReport>,
    document_timestamps: Vec<SignatureReport>,
    fallback_reports: Vec<SignatureReport>,
    signer_names: Vec<String>,
) -> ValidationReport {
    let latest = signatures.last().or_else(|| fallback_reports.last());
    let mut verdict_reports = if signatures.is_empty() {
        fallback_reports.clone()
    } else {
        let mut reports = signatures.clone();
        if !signer_chain_inconclusive(&signatures) {
            reports.extend(document_timestamps.clone());
        }
        reports
    };
    if verdict_reports.is_empty() {
        verdict_reports = fallback_reports.clone();
    }
    let representative = if document_timestamps.is_empty() {
        latest
    } else {
        representative_report(&verdict_reports).or(latest)
    };
    let standards = if document_timestamps.is_empty() || signer_chain_inconclusive(&signatures) {
        representative
            .map(|report| report.standards())
            .unwrap_or_else(|| standards_result_for(&[]))
    } else {
        aggregate_standards_result(&verdict_reports)
    };
    let mut pades_level = latest
        .map(|report| report.pades_level)
        .unwrap_or(PadesLevel::Unknown);
    if pades_level == PadesLevel::BaselineLT
        && document_timestamps
            .iter()
            .any(document_timestamp_is_trusted)
    {
        pades_level = PadesLevel::BaselineLTA;
    }

    ValidationReport {
        steps: representative
            .map(|report| report.steps.clone())
            .unwrap_or_default(),
        signer_name: latest.and_then(|report| report.signer_name.clone()),
        signer_names,
        signing_time: latest.and_then(|report| report.signing_time.clone()),
        verdict: aggregate_verdict(verdict_reports.iter().map(|report| report.verdict)),
        signatures,
        document_timestamps,
        standards,
        pades_level,
        preservation: preservation_assessment_for_level(pades_level),
    }
}

pub fn pades_level_for_signature_steps(
    steps: &[Step],
    is_pades_baseline_candidate: bool,
) -> PadesLevel {
    if !is_pades_baseline_candidate {
        return PadesLevel::Unknown;
    }
    if steps.iter().any(is_pades_level_blocking_failure) {
        return PadesLevel::Unknown;
    }
    if !steps.iter().any(|step| {
        matches!(
            step.kind,
            StepKind::SignatureVerifySignedAttributes | StepKind::SignatureVerifyContent
        ) && step.status == Status::Ok
    }) {
        return PadesLevel::Unknown;
    }

    let has_trusted_signature_timestamp = step_ok(steps, StepKind::TsaMessageImprint)
        && step_ok(steps, StepKind::TsaSignatureVerify)
        && step_ok(steps, StepKind::TsaExtendedKeyUsage)
        && step_ok(steps, StepKind::TsaCertificateChain);
    let has_embedded_validation_data = steps.iter().any(|step| {
        step.kind == StepKind::ByteRangeCoverage
            && step.status == Status::Ok
            && step.detail == "Covers signed revision; later revision adds validation data"
    });
    let has_valid_revocation_evidence = step_ok(steps, StepKind::RevocationSigner);

    if has_trusted_signature_timestamp
        && has_embedded_validation_data
        && has_valid_revocation_evidence
    {
        PadesLevel::BaselineLT
    } else if has_trusted_signature_timestamp {
        PadesLevel::BaselineT
    } else {
        PadesLevel::BaselineB
    }
}

pub fn preservation_assessment_for_level(level: PadesLevel) -> PreservationAssessment {
    match level {
        PadesLevel::Unknown => PreservationAssessment::unknown(
            "The signature is not recognized as a valid PAdES baseline profile",
        ),
        PadesLevel::BaselineB => PreservationAssessment {
            level: PreservationLevel::Basic,
            label: "Basic".to_owned(),
            detail: "PAdES-B-B: the document signature is intact, but no trusted timestamp was validated".to_owned(),
        },
        PadesLevel::BaselineT => PreservationAssessment {
            level: PreservationLevel::Timestamped,
            label: "Timestamped".to_owned(),
            detail: "PAdES-B-T: a trusted timestamp proves the signature existed at the timestamp time".to_owned(),
        },
        PadesLevel::BaselineLT => PreservationAssessment {
            level: PreservationLevel::LongTerm,
            label: "Long-term".to_owned(),
            detail: "PAdES-B-LT: trusted timestamp and validation evidence are available for long-term validation".to_owned(),
        },
        PadesLevel::BaselineLTA => PreservationAssessment {
            level: PreservationLevel::Archival,
            label: "Archive".to_owned(),
            detail: "PAdES-B-LTA: long-term validation evidence is protected by a trusted document timestamp".to_owned(),
        },
    }
}

fn is_pades_level_blocking_failure(step: &Step) -> bool {
    step.status == Status::Fail
        && matches!(
            step.kind,
            StepKind::ParsePDF
                | StepKind::SignatureFieldResolution
                | StepKind::ByteRangeCoverage
                | StepKind::ByteRangeBounds
                | StepKind::DocumentModifiedAfterSigning
                | StepKind::CmsStructure
                | StepKind::PadesBaselineRequirements
                | StepKind::SignerInfoPresent
                | StepKind::MessageDigestMatches
                | StepKind::MessageDigestAttribute
                | StepKind::SignerCertificatePresent
                | StepKind::SignatureVerifySignedAttributes
                | StepKind::SignatureVerifyContent
        )
}

fn step_ok(steps: &[Step], kind: StepKind) -> bool {
    steps
        .iter()
        .any(|step| step.kind == kind && step.status == Status::Ok)
}

fn document_timestamp_is_trusted(report: &SignatureReport) -> bool {
    !report.steps.iter().any(|step| step.status == Status::Fail)
        && step_ok(&report.steps, StepKind::DocumentTimestamp)
        && step_ok(&report.steps, StepKind::TsaMessageImprint)
        && step_ok(&report.steps, StepKind::TsaSignatureVerify)
        && step_ok(&report.steps, StepKind::TsaExtendedKeyUsage)
        && step_ok(&report.steps, StepKind::TsaCertificateChain)
}

fn signer_chain_inconclusive(signatures: &[SignatureReport]) -> bool {
    signatures.iter().any(|report| {
        report.steps.iter().any(|step| {
            step.kind == StepKind::SignerCertificateChain && step.status == Status::Warn
        })
    })
}

fn representative_report(reports: &[SignatureReport]) -> Option<&SignatureReport> {
    reports
        .iter()
        .find(|report| report.standards().indication == ValidationIndication::TotalFailed)
        .or_else(|| {
            reports
                .iter()
                .find(|report| report.verdict == Verdict::Invalid)
        })
        .or_else(|| {
            reports
                .iter()
                .find(|report| report.standards().indication == ValidationIndication::Indeterminate)
        })
        .or_else(|| {
            reports
                .iter()
                .find(|report| report.verdict == Verdict::Inconclusive)
        })
        .or_else(|| {
            reports
                .iter()
                .find(|report| report.verdict == Verdict::Warning)
        })
        .or_else(|| reports.last())
}

fn aggregate_standards_result(reports: &[SignatureReport]) -> StandardsValidationResult {
    if let Some(failed) = reports
        .iter()
        .map(SignatureReport::standards)
        .find(|standards| standards.indication == ValidationIndication::TotalFailed)
    {
        return failed;
    }
    if let Some(indeterminate) = reports
        .iter()
        .map(SignatureReport::standards)
        .find(|standards| standards.indication == ValidationIndication::Indeterminate)
    {
        return indeterminate;
    }
    StandardsValidationResult {
        indication: ValidationIndication::TotalPassed,
        sub_indication: ValidationSubIndication::None,
        diagnostic: None,
    }
}

pub fn verdict_for(steps: &[Step]) -> Verdict {
    match standards_result_for(steps).indication {
        ValidationIndication::TotalPassed => Verdict::Valid,
        ValidationIndication::TotalFailed => Verdict::Invalid,
        ValidationIndication::Indeterminate => {
            if steps
                .iter()
                .find(|step| step.status == Status::Warn)
                .map(is_soft_indeterminate_warning)
                .unwrap_or(false)
            {
                Verdict::Warning
            } else {
                Verdict::Inconclusive
            }
        }
    }
}

pub fn standards_result_for(steps: &[Step]) -> StandardsValidationResult {
    if let Some(failed) = steps.iter().find(|step| step.status == Status::Fail) {
        if failure_is_dominated_by_untrusted_signer_chain(failed) {
            if let Some(warning) = steps.iter().find(|step| {
                step.kind == StepKind::SignerCertificateChain && step.status == Status::Warn
            }) {
                return StandardsValidationResult {
                    indication: ValidationIndication::Indeterminate,
                    sub_indication: standards_sub_indication(warning, false),
                    diagnostic: Some(warning.detail.clone()),
                };
            }
        }
        if is_pkcs7_sha1_content_signature_failure(failed) {
            if let Some(warning) = steps.iter().find(|step| {
                step.kind == StepKind::SignerCertificateChain && step.status == Status::Warn
            }) {
                return StandardsValidationResult {
                    indication: ValidationIndication::Indeterminate,
                    sub_indication: standards_sub_indication(warning, false),
                    diagnostic: Some(warning.detail.clone()),
                };
            }
        }
        if failed.kind == StepKind::MessageDigestMatches
            && failed
                .detail
                .starts_with("unsupported digest algorithm 1.2.840.113549.1.1.5")
        {
            return StandardsValidationResult {
                indication: ValidationIndication::Indeterminate,
                sub_indication: ValidationSubIndication::HashFailure,
                diagnostic: Some(failed.detail.clone()),
            };
        }
        let sub_indication = standards_sub_indication(failed, true);
        let indication = match sub_indication {
            ValidationSubIndication::SigningCertificateNotFound => {
                ValidationIndication::Indeterminate
            }
            ValidationSubIndication::RevocationOutOfBoundsNoPoe => {
                ValidationIndication::Indeterminate
            }
            ValidationSubIndication::CertificateChainGeneralFailure => {
                ValidationIndication::Indeterminate
            }
            ValidationSubIndication::Revoked => ValidationIndication::Indeterminate,
            _ => ValidationIndication::TotalFailed,
        };
        return StandardsValidationResult {
            indication,
            sub_indication,
            diagnostic: Some(failed.detail.clone()),
        };
    }
    if let Some(warning) = steps.iter().find(|step| step.status == Status::Warn) {
        return StandardsValidationResult {
            indication: ValidationIndication::Indeterminate,
            sub_indication: standards_sub_indication(warning, false),
            diagnostic: Some(warning.detail.clone()),
        };
    }
    StandardsValidationResult {
        indication: ValidationIndication::TotalPassed,
        sub_indication: ValidationSubIndication::None,
        diagnostic: None,
    }
}

fn failure_is_dominated_by_untrusted_signer_chain(step: &Step) -> bool {
    is_timestamp_evidence_step(step)
        || matches!(
            step.kind,
            StepKind::PadesBaselineRequirements | StepKind::SignatureFieldResolution
        )
}

fn is_pkcs7_sha1_content_signature_failure(step: &Step) -> bool {
    step.kind == StepKind::SignatureVerifyContent
        && step.detail == "signature does not match content"
}

fn is_timestamp_evidence_step(step: &Step) -> bool {
    matches!(
        step.kind,
        StepKind::TsaTimestamp
            | StepKind::TsaMessageImprint
            | StepKind::TsaSignatureVerify
            | StepKind::TsaExtendedKeyUsage
            | StepKind::TsaCertificateChain
            | StepKind::DocumentTimestamp
    )
}

fn standards_sub_indication(step: &Step, failed: bool) -> ValidationSubIndication {
    match step.kind {
        StepKind::ParsePDF
        | StepKind::SignatureFieldResolution
        | StepKind::ByteRangeCoverage
        | StepKind::ByteRangeBounds
        | StepKind::CmsStructure
        | StepKind::PadesBaselineRequirements
        | StepKind::SignerInfoPresent => ValidationSubIndication::FormatFailure,
        StepKind::DocumentModifiedAfterSigning => {
            ValidationSubIndication::DocumentModifiedAfterSigning
        }
        StepKind::MessageDigestAttribute | StepKind::MessageDigestMatches => {
            ValidationSubIndication::HashFailure
        }
        StepKind::SignatureVerifySignedAttributes
        | StepKind::SignatureVerifyContent
        | StepKind::TsaSignatureVerify => ValidationSubIndication::SignatureCryptoFailure,
        StepKind::SignerCertificatePresent => ValidationSubIndication::SigningCertificateNotFound,
        StepKind::SignerCertificateValidity => ValidationSubIndication::RevocationOutOfBoundsNoPoe,
        StepKind::SignerCertificateKeyUsage | StepKind::SignerCertificateExtendedKeyUsage => {
            ValidationSubIndication::CryptographicConstraintsFailure
        }
        StepKind::SignerCertificateChain | StepKind::TsaCertificateChain => {
            ValidationSubIndication::CertificateChainGeneralFailure
        }
        StepKind::TsaExtendedKeyUsage => ValidationSubIndication::CryptographicConstraintsFailure,
        StepKind::RevocationSigner => {
            if failed && step.detail.to_ascii_lowercase().contains("revoked") {
                ValidationSubIndication::Revoked
            } else {
                ValidationSubIndication::RevocationOutOfBoundsNoPoe
            }
        }
        StepKind::TsaTimestamp | StepKind::TsaMessageImprint | StepKind::DocumentTimestamp => {
            ValidationSubIndication::TimestampGeneralFailure
        }
        StepKind::Other => {
            if failed {
                ValidationSubIndication::CryptographicConstraintsFailure
            } else {
                ValidationSubIndication::CertificateChainGeneralFailure
            }
        }
    }
}

fn is_soft_indeterminate_warning(step: &Step) -> bool {
    matches!(
        step.kind,
        StepKind::TsaTimestamp
            | StepKind::TsaMessageImprint
            | StepKind::TsaSignatureVerify
            | StepKind::TsaExtendedKeyUsage
            | StepKind::TsaCertificateChain
    )
}

fn aggregate_verdict(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
    let verdicts: Vec<Verdict> = verdicts.into_iter().collect();
    if verdicts.contains(&Verdict::Error) {
        Verdict::Error
    } else if verdicts.contains(&Verdict::Invalid) {
        Verdict::Invalid
    } else if verdicts.contains(&Verdict::Inconclusive) {
        Verdict::Inconclusive
    } else if verdicts.contains(&Verdict::Warning) {
        Verdict::Warning
    } else if verdicts.contains(&Verdict::NoSignatures) {
        Verdict::NoSignatures
    } else {
        Verdict::Valid
    }
}

pub fn format_int_dot(value: usize) -> String {
    let raw = value.to_string();
    let mut out = String::new();
    for (i, ch) in raw.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push('.');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pades_preservation_detects_basic_profile() {
        let steps = basic_signature_steps();

        let level = pades_level_for_signature_steps(&steps, true);
        let preservation = preservation_assessment_for_level(level);

        assert_eq!(level, PadesLevel::BaselineB);
        assert_eq!(preservation.level, PreservationLevel::Basic);
        assert_eq!(preservation.label, "Basic");
    }

    #[test]
    fn pades_preservation_promotes_trusted_timestamp_to_t() {
        let mut steps = basic_signature_steps();
        steps.extend(trusted_timestamp_steps());

        let level = pades_level_for_signature_steps(&steps, true);
        let preservation = preservation_assessment_for_level(level);

        assert_eq!(level, PadesLevel::BaselineT);
        assert_eq!(preservation.level, PreservationLevel::Timestamped);
        assert_eq!(preservation.label, "Timestamped");
    }

    #[test]
    fn pades_preservation_promotes_embedded_validation_data_and_revocation_to_lt() {
        let mut steps = basic_signature_steps();
        steps.extend(trusted_timestamp_steps());
        steps.push(Step::new(
            StepKind::ByteRangeCoverage,
            Status::Ok,
            "Covers signed revision; later revision adds validation data",
        ));
        steps.push(Step::new(
            StepKind::RevocationSigner,
            Status::Ok,
            "certificate is not listed in the current CRL",
        ));

        let level = pades_level_for_signature_steps(&steps, true);
        let preservation = preservation_assessment_for_level(level);

        assert_eq!(level, PadesLevel::BaselineLT);
        assert_eq!(preservation.level, PreservationLevel::LongTerm);
        assert_eq!(preservation.label, "Long-term");
    }

    #[test]
    fn aggregate_preservation_promotes_lt_with_trusted_document_timestamp_to_lta() {
        let signature = signature_report(PadesLevel::BaselineLT);
        let document_timestamp = SignatureReport {
            index: 2,
            total: 2,
            signed_revision_size: 10,
            current_file_size: 10,
            byte_range: vec![0, 1, 2, 3],
            steps: trusted_document_timestamp_steps(),
            signer_name: None,
            signing_time: None,
            signer_certificate: None,
            certificate_chain: vec![],
            timestamp_details: None,
            verdict: Verdict::Valid,
            pades_level: PadesLevel::Unknown,
            preservation: PreservationAssessment::unknown("document timestamp"),
        };

        let report = aggregate_report(
            vec![signature],
            vec![document_timestamp],
            vec![],
            vec!["Signer".to_owned()],
        );

        assert_eq!(report.pades_level, PadesLevel::BaselineLTA);
        assert_eq!(report.preservation.level, PreservationLevel::Archival);
        assert_eq!(report.preservation.label, "Archive");
    }

    #[test]
    fn pades_preservation_does_not_promote_untrusted_timestamp() {
        let mut steps = basic_signature_steps();
        steps.push(Step::new(StepKind::TsaMessageImprint, Status::Ok, "ok"));
        steps.push(Step::new(StepKind::TsaSignatureVerify, Status::Ok, "ok"));
        steps.push(Step::new(StepKind::TsaExtendedKeyUsage, Status::Ok, "ok"));
        steps.push(Step::new(
            StepKind::TsaCertificateChain,
            Status::Warn,
            "no path to configured timestamp trust anchors or pins",
        ));

        assert_eq!(
            pades_level_for_signature_steps(&steps, true),
            PadesLevel::BaselineB
        );
    }

    #[test]
    fn pades_preservation_blocks_malformed_baseline_signature() {
        let mut steps = basic_signature_steps();
        steps.push(Step::new(
            StepKind::PadesBaselineRequirements,
            Status::Fail,
            "PAdES signatures must use detached CMS content; encapsulated eContent is present",
        ));

        let level = pades_level_for_signature_steps(&steps, true);

        assert_eq!(level, PadesLevel::Unknown);
    }

    fn basic_signature_steps() -> Vec<Step> {
        vec![
            Step::new(StepKind::ParsePDF, Status::Ok, "ok"),
            Step::new(StepKind::ByteRangeCoverage, Status::Ok, "ok"),
            Step::new(StepKind::ByteRangeBounds, Status::Ok, "ok"),
            Step::new(StepKind::CmsStructure, Status::Ok, "ok"),
            Step::new(StepKind::SignerInfoPresent, Status::Ok, "ok"),
            Step::new(StepKind::MessageDigestMatches, Status::Ok, "ok"),
            Step::new(StepKind::SignatureVerifySignedAttributes, Status::Ok, "ok"),
            Step::new(StepKind::SignerCertificatePresent, Status::Ok, "ok"),
        ]
    }

    fn trusted_timestamp_steps() -> Vec<Step> {
        vec![
            Step::new(StepKind::TsaMessageImprint, Status::Ok, "ok"),
            Step::new(StepKind::TsaSignatureVerify, Status::Ok, "ok"),
            Step::new(StepKind::TsaExtendedKeyUsage, Status::Ok, "ok"),
            Step::new(StepKind::TsaCertificateChain, Status::Ok, "ok"),
        ]
    }

    fn trusted_document_timestamp_steps() -> Vec<Step> {
        let mut steps = vec![Step::new(StepKind::DocumentTimestamp, Status::Ok, "ok")];
        steps.extend(trusted_timestamp_steps());
        steps
    }

    fn signature_report(pades_level: PadesLevel) -> SignatureReport {
        SignatureReport {
            index: 1,
            total: 1,
            signed_revision_size: 10,
            current_file_size: 10,
            byte_range: vec![0, 1, 2, 3],
            steps: basic_signature_steps(),
            signer_name: Some("Signer".to_owned()),
            signing_time: None,
            signer_certificate: None,
            certificate_chain: vec![],
            timestamp_details: None,
            verdict: Verdict::Valid,
            pades_level,
            preservation: preservation_assessment_for_level(pades_level),
        }
    }
}
