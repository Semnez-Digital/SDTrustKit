package com.sdtrustkit

import android.util.Base64
import kotlinx.serialization.Serializable

@Serializable
data class VerificationOptions(
    val signerTrustAnchorsDerBase64: List<String> = emptyList(),
    val signerTrustAnchorSets: List<TimedTrustAnchorSet> = emptyList(),
    val timestampTrustAnchorsDerBase64: List<String> = emptyList(),
    val timestampTrustAnchorSets: List<TimedTrustAnchorSet> = emptyList(),
    val timestampCertificateSha256Pins: List<String> = emptyList(),
) {
    companion object {
        fun fromDer(
            signerTrustAnchorsDer: List<ByteArray> = emptyList(),
            signerTrustAnchorSets: List<TimedTrustAnchorSet> = emptyList(),
            timestampTrustAnchorsDer: List<ByteArray> = emptyList(),
            timestampTrustAnchorSets: List<TimedTrustAnchorSet> = emptyList(),
            timestampCertificateSha256Pins: List<String> = emptyList(),
        ): VerificationOptions =
            VerificationOptions(
                signerTrustAnchorsDerBase64 = signerTrustAnchorsDer.map(::base64),
                signerTrustAnchorSets = signerTrustAnchorSets,
                timestampTrustAnchorsDerBase64 = timestampTrustAnchorsDer.map(::base64),
                timestampTrustAnchorSets = timestampTrustAnchorSets,
                timestampCertificateSha256Pins = timestampCertificateSha256Pins,
            )
    }
}

@Serializable
data class TimedTrustAnchorSet(
    val validFromUnixSeconds: Double? = null,
    val validUntilUnixSeconds: Double? = null,
    val anchorsDerBase64: List<String> = emptyList(),
) {
    companion object {
        fun fromDer(
            validFromUnixSeconds: Double? = null,
            validUntilUnixSeconds: Double? = null,
            anchorsDer: List<ByteArray>,
        ): TimedTrustAnchorSet =
            TimedTrustAnchorSet(
                validFromUnixSeconds = validFromUnixSeconds,
                validUntilUnixSeconds = validUntilUnixSeconds,
                anchorsDerBase64 = anchorsDer.map(::base64),
            )
    }
}

@Serializable
data class RevocationOptions(
    val nowUnixSeconds: Double? = null,
    val crlCacheEntries: List<CrlCacheEntry> = emptyList(),
)

@Serializable
data class CrlCacheEntry(
    val url: String? = null,
    val cacheKeySha256: String? = null,
    val validUntilUnixSeconds: Double,
    val derBase64: String,
) {
    companion object {
        fun fromUrl(
            url: String,
            validUntilUnixSeconds: Double,
            der: ByteArray,
        ): CrlCacheEntry =
            CrlCacheEntry(
                url = url,
                validUntilUnixSeconds = validUntilUnixSeconds,
                derBase64 = base64(der),
            )

        fun fromCacheKey(
            cacheKeySha256: String,
            validUntilUnixSeconds: Double,
            der: ByteArray,
        ): CrlCacheEntry =
            CrlCacheEntry(
                cacheKeySha256 = cacheKeySha256,
                validUntilUnixSeconds = validUntilUnixSeconds,
                derBase64 = base64(der),
            )
    }
}

private fun base64(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.NO_WRAP)
