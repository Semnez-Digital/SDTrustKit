package com.sdtrustkit

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ValidationReport(
    val steps: List<ValidationStep>,
    val signerName: String? = null,
    val signerNames: List<String> = emptyList(),
    val signingTime: String? = null,
    val verdict: ValidationVerdict,
    val signatures: List<SignatureReport> = emptyList(),
    val documentTimestamps: List<SignatureReport> = emptyList(),
    val standards: StandardsValidationResult,
    val padesLevel: PadesLevel,
    val preservation: PreservationAssessment,
)

@Serializable
data class SignatureReport(
    val index: Int,
    val total: Int,
    val signedRevisionSize: Int,
    val currentFileSize: Int,
    val byteRange: List<Int>,
    val steps: List<ValidationStep>,
    val signerName: String? = null,
    val signingTime: String? = null,
    val signerCertificate: CertificateDetails? = null,
    val certificateChain: List<CertificateDetails> = emptyList(),
    val timestampDetails: TimestampDetails? = null,
    val verdict: ValidationVerdict,
    val padesLevel: PadesLevel,
    val preservation: PreservationAssessment,
)

@Serializable
data class ValidationStep(
    val kind: StepKind,
    val name: String,
    val status: StepStatus,
    val detail: String,
)

@Serializable
data class StandardsValidationResult(
    val indication: ValidationIndication,
    val subIndication: ValidationSubIndication,
    val diagnostic: String? = null,
)

@Serializable
data class CertificateDetails(
    val der: List<Int>? = null,
    val subjectSummary: String,
    val issuerSummary: String,
    val commonName: String? = null,
    val serialNumberHex: String,
    val sha1Fingerprint: String,
    val sha256Fingerprint: String,
)

@Serializable
data class TimestampDetails(
    val timestampTime: String? = null,
    val policyOID: String? = null,
    val serialNumberHex: String? = null,
    val messageImprintAlgorithm: String? = null,
    val messageImprintHash: String? = null,
    val tsaCertificate: CertificateDetails? = null,
    val tsaCertificateChain: List<CertificateDetails> = emptyList(),
    val trustDetail: String? = null,
)

@Serializable
data class PreservationAssessment(
    val level: PreservationLevel,
    val label: String,
    val detail: String,
)

@Serializable
enum class PadesLevel {
    @SerialName("unknown")
    Unknown,

    @SerialName("baselineB")
    BaselineB,

    @SerialName("baselineT")
    BaselineT,

    @SerialName("baselineLT")
    BaselineLT,

    @SerialName("baselineLTA")
    BaselineLTA,
}

@Serializable
enum class PreservationLevel {
    @SerialName("unknown")
    Unknown,

    @SerialName("basic")
    Basic,

    @SerialName("timestamped")
    Timestamped,

    @SerialName("longTerm")
    LongTerm,

    @SerialName("archival")
    Archival,
}

@Serializable
enum class StepStatus {
    @SerialName("ok")
    Ok,

    @SerialName("fail")
    Fail,

    @SerialName("warn")
    Warn,

    @SerialName("skip")
    Skip,
}

@Serializable
enum class ValidationVerdict {
    @SerialName("error")
    Error,

    @SerialName("valid")
    Valid,

    @SerialName("warning")
    Warning,

    @SerialName("inconclusive")
    Inconclusive,

    @SerialName("invalid")
    Invalid,

    @SerialName("noSignatures")
    NoSignatures,
}

@Serializable
enum class ValidationIndication {
    @SerialName("passed")
    TotalPassed,

    @SerialName("failed")
    TotalFailed,

    @SerialName("needsEvidence")
    Indeterminate,
}

@Serializable
enum class ValidationSubIndication {
    @SerialName("none")
    None,

    @SerialName("formatIssue")
    FormatFailure,

    @SerialName("documentModifiedAfterSigning")
    DocumentModifiedAfterSigning,

    @SerialName("documentHashMismatch")
    HashFailure,

    @SerialName("signatureCryptographyIssue")
    SignatureCryptoFailure,

    @SerialName("signingCertificateMissing")
    SigningCertificateNotFound,

    @SerialName("certificateChainIssue")
    CertificateChainGeneralFailure,

    @SerialName("revocationEvidenceUnavailable")
    RevocationOutOfBoundsNoPoe,

    @SerialName("certificateRevoked")
    Revoked,

    @SerialName("timestampEvidenceIssue")
    TimestampGeneralFailure,

    @SerialName("cryptographicConstraintIssue")
    CryptographicConstraintsFailure,
}

@Serializable
enum class StepKind {
    @SerialName("parsePDF")
    ParsePDF,

    @SerialName("signatureFieldResolution")
    SignatureFieldResolution,

    @SerialName("byteRangeCoverage")
    ByteRangeCoverage,

    @SerialName("byteRangeBounds")
    ByteRangeBounds,

    @SerialName("documentModifiedAfterSigning")
    DocumentModifiedAfterSigning,

    @SerialName("cmsStructure")
    CmsStructure,

    @SerialName("padesBaselineRequirements")
    PadesBaselineRequirements,

    @SerialName("signerInfoPresent")
    SignerInfoPresent,

    @SerialName("messageDigestMatches")
    MessageDigestMatches,

    @SerialName("messageDigestAttribute")
    MessageDigestAttribute,

    @SerialName("signerCertificatePresent")
    SignerCertificatePresent,

    @SerialName("signerCertificateValidity")
    SignerCertificateValidity,

    @SerialName("signerCertificateKeyUsage")
    SignerCertificateKeyUsage,

    @SerialName("signerCertificateExtendedKeyUsage")
    SignerCertificateExtendedKeyUsage,

    @SerialName("signatureVerifySignedAttributes")
    SignatureVerifySignedAttributes,

    @SerialName("signatureVerifyContent")
    SignatureVerifyContent,

    @SerialName("signerCertificateChain")
    SignerCertificateChain,

    @SerialName("tsaTimestamp")
    TsaTimestamp,

    @SerialName("tsaMessageImprint")
    TsaMessageImprint,

    @SerialName("tsaSignatureVerify")
    TsaSignatureVerify,

    @SerialName("tsaExtendedKeyUsage")
    TsaExtendedKeyUsage,

    @SerialName("tsaCertificateChain")
    TsaCertificateChain,

    @SerialName("documentTimestamp")
    DocumentTimestamp,

    @SerialName("revocationSigner")
    RevocationSigner,

    @SerialName("other")
    Other,
}
