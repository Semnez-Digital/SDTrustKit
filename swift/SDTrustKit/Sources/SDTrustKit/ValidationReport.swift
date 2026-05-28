import Foundation

public struct ValidationReport: Decodable, Equatable, Sendable {
    public let steps: [ValidationStep]
    public let signerName: String?
    public let signerNames: [String]
    public let signingTime: String?
    public let verdict: ValidationVerdict
    public let signatures: [SignatureReport]
    public let documentTimestamps: [SignatureReport]
    public let standards: StandardsValidationResult
}

public struct SignatureReport: Decodable, Equatable, Sendable {
    public let index: Int
    public let total: Int
    public let signedRevisionSize: Int
    public let currentFileSize: Int
    public let byteRange: [Int]
    public let steps: [ValidationStep]
    public let signerName: String?
    public let signingTime: String?
    public let signerCertificate: CertificateDetails?
    public let certificateChain: [CertificateDetails]
    public let timestampDetails: TimestampDetails?
    public let verdict: ValidationVerdict
}

public struct ValidationStep: Decodable, Equatable, Sendable {
    public let kind: StepKind
    public let name: String
    public let status: StepStatus
    public let detail: String
}

public struct StandardsValidationResult: Decodable, Equatable, Sendable {
    public let indication: ValidationIndication
    public let subIndication: ValidationSubIndication
    public let diagnostic: String?
}

public struct CertificateDetails: Decodable, Equatable, Sendable {
    public let der: [UInt8]?
    public let subjectSummary: String
    public let issuerSummary: String
    public let commonName: String?
    public let serialNumberHex: String
    public let sha1Fingerprint: String
    public let sha256Fingerprint: String
}

public struct TimestampDetails: Decodable, Equatable, Sendable {
    public let timestampTime: String?
    public let policyOID: String?
    public let serialNumberHex: String?
    public let messageImprintAlgorithm: String?
    public let messageImprintHash: String?
    public let tsaCertificate: CertificateDetails?
    public let tsaCertificateChain: [CertificateDetails]
    public let trustDetail: String?
}

public enum StepStatus: String, Decodable, Sendable {
    case ok
    case fail
    case warn
    case skip
}

public enum ValidationVerdict: String, Decodable, Sendable {
    case error
    case valid
    case warning
    case inconclusive
    case invalid
    case noSignatures
}

public enum ValidationIndication: String, Decodable, Sendable {
    case passed
    case failed
    case needsEvidence
}

public enum ValidationSubIndication: String, Decodable, Sendable {
    case none
    case formatIssue
    case documentModifiedAfterSigning
    case documentHashMismatch
    case signatureCryptographyIssue
    case signingCertificateMissing
    case certificateChainIssue
    case revocationEvidenceUnavailable
    case certificateRevoked
    case timestampEvidenceIssue
    case cryptographicConstraintIssue
}

public enum StepKind: String, Decodable, Sendable {
    case parsePDF
    case signatureFieldResolution
    case byteRangeCoverage
    case byteRangeBounds
    case documentModifiedAfterSigning
    case cmsStructure
    case padesBaselineRequirements
    case signerInfoPresent
    case messageDigestMatches
    case messageDigestAttribute
    case signerCertificatePresent
    case signerCertificateValidity
    case signerCertificateKeyUsage
    case signerCertificateExtendedKeyUsage
    case signatureVerifySignedAttributes
    case signatureVerifyContent
    case signerCertificateChain
    case tsaTimestamp
    case tsaMessageImprint
    case tsaSignatureVerify
    case tsaExtendedKeyUsage
    case tsaCertificateChain
    case documentTimestamp
    case revocationSigner
    case other
}

extension JSONDecoder {
    static var rustReport: JSONDecoder {
        JSONDecoder()
    }
}
