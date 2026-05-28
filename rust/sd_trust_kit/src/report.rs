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
}

impl SignatureReport {
    pub fn standards(&self) -> StandardsValidationResult {
        standards_result_for(&self.steps)
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
        Self {
            steps,
            signer_name,
            signer_names,
            signing_time,
            verdict,
            signatures: vec![],
            document_timestamps: vec![],
            standards,
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
    }
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
