import Darwin
import Foundation

#if SD_TRUST_KIT_STATIC
import CSDTrustKit
#endif

public final class SDTrustKit {
    private let library: SDValidationLibrary

    public init(libraryURL: URL? = nil) throws {
        #if SD_TRUST_KIT_STATIC
        self.library = try SDValidationLibrary(url: libraryURL)
        #else
        self.library = try SDValidationLibrary(url: libraryURL ?? Self.defaultLibraryURL())
        #endif
    }

    public func verifyPDF(_ pdf: Data) throws -> ValidationReport {
        try callReportFunction(pdf: pdf) { bytes, count in
            library.verifyPDF(bytes, count)
        }
    }

    public func verifyPDF(_ pdf: Data, options: VerificationOptions) throws -> ValidationReport {
        let optionsJSON = try encodeJSONString(options)
        return try callReportFunction(pdf: pdf) { bytes, count in
            optionsJSON.withCString { optionsCString in
                library.verifyPDFWithOptions(bytes, count, optionsCString)
            }
        }
    }

    public func verifyPDFIncludingRevocation(
        _ pdf: Data,
        verificationOptions: VerificationOptions = VerificationOptions(),
        revocationOptions: RevocationOptions
    ) throws -> ValidationReport {
        let verificationOptionsJSON = try encodeJSONString(verificationOptions)
        let revocationOptionsJSON = try encodeJSONString(revocationOptions)
        return try callReportFunction(pdf: pdf) { bytes, count in
            verificationOptionsJSON.withCString { verificationOptionsCString in
                revocationOptionsJSON.withCString { revocationOptionsCString in
                    library.verifyPDFIncludingRevocation(
                        bytes,
                        count,
                        verificationOptionsCString,
                        revocationOptionsCString
                    )
                }
            }
        }
    }

    private func callReportFunction(
        pdf: Data,
        _ function: (UnsafePointer<UInt8>?, Int) -> UnsafeMutablePointer<CChar>?
    ) throws -> ValidationReport {
        let resultPointer: UnsafeMutablePointer<CChar>? = pdf.withUnsafeBytes { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress
            return function(bytes, rawBuffer.count)
        }
        guard let resultPointer else {
            throw SDValidationError.nullResult
        }
        defer {
            library.freeString(resultPointer)
        }

        let json = String(cString: resultPointer)
        let data = Data(json.utf8)
        if let ffiError = try? JSONDecoder.rustReport.decode(FfiErrorEnvelope.self, from: data) {
            throw SDValidationError.ffi(code: ffiError.error.code, message: ffiError.error.message)
        }
        return try JSONDecoder.rustReport.decode(ValidationReport.self, from: data)
    }

    private static func defaultLibraryURL() -> URL {
        if let path = ProcessInfo.processInfo.environment["SD_TRUST_KIT_DYLIB"] {
            return URL(fileURLWithPath: path)
        }

        let packageDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return packageDirectory
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("rust/sd_trust_kit/target/release/libsd_trust_kit.dylib")
    }
}

private final class SDValidationLibrary {
    typealias VerifyPDF = @convention(c) (UnsafePointer<UInt8>?, Int) -> UnsafeMutablePointer<CChar>?
    typealias VerifyPDFWithOptions = @convention(c) (
        UnsafePointer<UInt8>?,
        Int,
        UnsafePointer<CChar>?
    ) -> UnsafeMutablePointer<CChar>?
    typealias VerifyPDFIncludingRevocation = @convention(c) (
        UnsafePointer<UInt8>?,
        Int,
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?
    ) -> UnsafeMutablePointer<CChar>?
    typealias FreeString = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

    let verifyPDF: VerifyPDF
    let verifyPDFWithOptions: VerifyPDFWithOptions
    let verifyPDFIncludingRevocation: VerifyPDFIncludingRevocation
    let freeString: FreeString

    private let handle: UnsafeMutableRawPointer?

    init(url: URL?) throws {
        #if SD_TRUST_KIT_STATIC
        guard let url else {
            self.handle = nil
            self.verifyPDF = { bytes, count in
                sd_trust_kit_verify_pdf_json(bytes, count)
            }
            self.verifyPDFWithOptions = { bytes, count, options in
                sd_trust_kit_verify_pdf_with_options_json(bytes, count, options)
            }
            self.verifyPDFIncludingRevocation = { bytes, count, verificationOptions, revocationOptions in
                sd_trust_kit_verify_pdf_including_revocation_with_options_json(
                    bytes,
                    count,
                    verificationOptions,
                    revocationOptions
                )
            }
            self.freeString = { pointer in
                sd_trust_kit_free_string(pointer)
            }
            return
        }
        #else
        guard let url else {
            throw SDValidationError.libraryLoadFailed(path: "", reason: "No dynamic library URL was provided")
        }
        #endif

        guard let handle = dlopen(url.path, RTLD_NOW | RTLD_LOCAL) else {
            let reason = dlerror().map { String(cString: $0) } ?? "unknown dlopen error"
            throw SDValidationError.libraryLoadFailed(path: url.path, reason: reason)
        }
        self.handle = handle
        do {
            self.verifyPDF = try Self.symbol(handle, "sd_trust_kit_verify_pdf_json")
            self.verifyPDFWithOptions = try Self.symbol(handle, "sd_trust_kit_verify_pdf_with_options_json")
            self.verifyPDFIncludingRevocation = try Self.symbol(
                handle,
                "sd_trust_kit_verify_pdf_including_revocation_with_options_json"
            )
            self.freeString = try Self.symbol(handle, "sd_trust_kit_free_string")
        } catch {
            dlclose(handle)
            throw error
        }
    }

    deinit {
        if let handle {
            dlclose(handle)
        }
    }

    private static func symbol<T>(_ handle: UnsafeMutableRawPointer, _ name: String) throws -> T {
        guard let pointer = dlsym(handle, name) else {
            throw SDValidationError.symbolMissing(name)
        }
        return unsafeBitCast(pointer, to: T.self)
    }
}

private func encodeJSONString<T: Encodable>(_ value: T) throws -> String {
    let data = try JSONEncoder.rustOptions.encode(value)
    guard let string = String(data: data, encoding: .utf8) else {
        throw SDValidationError.optionsEncodingFailed
    }
    return string
}

private struct FfiErrorEnvelope: Decodable {
    let error: FfiError
}

private struct FfiError: Decodable {
    let code: String
    let message: String
}

public enum SDValidationError: Error, Equatable {
    case libraryLoadFailed(path: String, reason: String)
    case symbolMissing(String)
    case nullResult
    case optionsEncodingFailed
    case ffi(code: String, message: String)
}
