import Foundation

public struct VerificationOptions: Encodable, Equatable, Sendable {
    public var signerTrustAnchorsDerBase64: [String]
    public var signerTrustAnchorSets: [TimedTrustAnchorSet]
    public var timestampTrustAnchorsDerBase64: [String]
    public var timestampTrustAnchorSets: [TimedTrustAnchorSet]
    public var timestampCertificateSha256Pins: [String]

    public init(
        signerTrustAnchorsDer: [Data] = [],
        signerTrustAnchorSets: [TimedTrustAnchorSet] = [],
        timestampTrustAnchorsDer: [Data] = [],
        timestampTrustAnchorSets: [TimedTrustAnchorSet] = [],
        timestampCertificateSha256Pins: [String] = []
    ) {
        self.signerTrustAnchorsDerBase64 = signerTrustAnchorsDer.map { $0.base64EncodedString() }
        self.signerTrustAnchorSets = signerTrustAnchorSets
        self.timestampTrustAnchorsDerBase64 = timestampTrustAnchorsDer.map { $0.base64EncodedString() }
        self.timestampTrustAnchorSets = timestampTrustAnchorSets
        self.timestampCertificateSha256Pins = timestampCertificateSha256Pins
    }
}

public struct TimedTrustAnchorSet: Encodable, Equatable, Sendable {
    public var validFromUnixSeconds: Double?
    public var validUntilUnixSeconds: Double?
    public var anchorsDerBase64: [String]

    public init(
        validFromUnixSeconds: Double? = nil,
        validUntilUnixSeconds: Double? = nil,
        anchorsDer: [Data]
    ) {
        self.validFromUnixSeconds = validFromUnixSeconds
        self.validUntilUnixSeconds = validUntilUnixSeconds
        self.anchorsDerBase64 = anchorsDer.map { $0.base64EncodedString() }
    }
}

public struct RevocationOptions: Encodable, Equatable, Sendable {
    public var nowUnixSeconds: Double?
    public var crlCacheEntries: [CrlCacheEntry]

    public init(nowUnixSeconds: Double? = nil, crlCacheEntries: [CrlCacheEntry] = []) {
        self.nowUnixSeconds = nowUnixSeconds
        self.crlCacheEntries = crlCacheEntries
    }
}

public struct CrlCacheEntry: Encodable, Equatable, Sendable {
    public var url: String?
    public var cacheKeySha256: String?
    public var validUntilUnixSeconds: Double
    public var derBase64: String

    public init(
        url: String,
        validUntilUnixSeconds: Double,
        der: Data
    ) {
        self.url = url
        self.cacheKeySha256 = nil
        self.validUntilUnixSeconds = validUntilUnixSeconds
        self.derBase64 = der.base64EncodedString()
    }

    public init(
        cacheKeySha256: String,
        validUntilUnixSeconds: Double,
        der: Data
    ) {
        self.url = nil
        self.cacheKeySha256 = cacheKeySha256
        self.validUntilUnixSeconds = validUntilUnixSeconds
        self.derBase64 = der.base64EncodedString()
    }
}

extension JSONEncoder {
    static var rustOptions: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
