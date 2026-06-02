package com.sdtrustkit

internal object SDTrustKitNative {
    @Volatile
    private var loadedLibraryName: String? = null

    @Synchronized
    fun load(libraryName: String) {
        if (loadedLibraryName == libraryName) {
            return
        }
        System.loadLibrary(libraryName)
        loadedLibraryName = libraryName
    }

    external fun verifyPdfJson(pdf: ByteArray): String

    external fun verifyPdfWithOptionsJson(
        pdf: ByteArray,
        optionsJson: String?,
    ): String

    external fun verifyPdfIncludingRevocationJson(
        pdf: ByteArray,
        verificationOptionsJson: String?,
        revocationOptionsJson: String?,
    ): String
}
