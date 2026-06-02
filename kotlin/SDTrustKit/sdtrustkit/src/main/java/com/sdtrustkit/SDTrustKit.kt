package com.sdtrustkit

import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class SDTrustKit(
    loadNativeLibrary: Boolean = true,
    nativeLibraryName: String = "sd_trust_kit",
) {
    init {
        if (loadNativeLibrary) {
            SDTrustKitNative.load(nativeLibraryName)
        }
    }

    fun verifyPdf(pdf: ByteArray): ValidationReport =
        decodeReport(SDTrustKitNative.verifyPdfJson(pdf))

    fun verifyPdf(pdf: ByteArray, options: VerificationOptions): ValidationReport =
        decodeReport(
            SDTrustKitNative.verifyPdfWithOptionsJson(
                pdf,
                RustJson.encodeToString(options),
            ),
        )

    fun verifyPdfIncludingRevocation(
        pdf: ByteArray,
        verificationOptions: VerificationOptions = VerificationOptions(),
        revocationOptions: RevocationOptions,
    ): ValidationReport =
        decodeReport(
            SDTrustKitNative.verifyPdfIncludingRevocationJson(
                pdf,
                RustJson.encodeToString(verificationOptions),
                RustJson.encodeToString(revocationOptions),
            ),
        )

    private fun decodeReport(json: String): ValidationReport {
        val error = try {
            RustJson.decodeFromString<FfiErrorEnvelope>(json)
        } catch (_: SerializationException) {
            null
        }
        if (error != null) {
            throw SDTrustKitException.Ffi(error.error.code, error.error.message)
        }
        return RustJson.decodeFromString(json)
    }
}

sealed class SDTrustKitException(message: String) : RuntimeException(message) {
    class Ffi(val code: String, override val message: String) :
        SDTrustKitException("$code: $message")
}

internal object RustJson {
    val format = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
    }

    inline fun <reified T> decodeFromString(json: String): T =
        format.decodeFromString(json)

    inline fun <reified T> encodeToString(value: T): String =
        format.encodeToString(value)
}

@Serializable
private data class FfiErrorEnvelope(
    val error: FfiError,
)

@Serializable
private data class FfiError(
    val code: String,
    val message: String,
)
