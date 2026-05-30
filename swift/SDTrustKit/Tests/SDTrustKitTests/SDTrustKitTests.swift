import Foundation
import Testing
@testable import SDTrustKit

@Suite(.serialized)
struct SDTrustKitTests {
    @Test
    func verifiesPDFThroughRustCore() throws {
        let validator = try SDTrustKit()

        let report = try validator.verifyPDF(Data("not a pdf".utf8))

        #expect(report.verdict == .error)
        #expect(report.standards.indication == .failed)
        #expect(report.signatures.isEmpty)
        #expect(report.steps.first?.kind == .parsePDF)
    }

    @Test
    func reportsUnsignedPDFSeparately() throws {
        let validator = try SDTrustKit()
        let pdf = Data("%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nstartxref\n0\n%%EOF\n".utf8)

        let report = try validator.verifyPDF(pdf)

        #expect(report.verdict == .noSignatures)
        #expect(report.signatures.isEmpty)
        #expect(report.steps.first?.status == .ok)
    }

    @Test
    func reportsEncryptedPDFAsError() throws {
        let paths = TestPaths()
        guard FileManager.default.fileExists(atPath: paths.dssOpenProtectedPDF.path) else {
            return
        }
        let validator = try SDTrustKit()
        let pdf = try Data(contentsOf: paths.dssOpenProtectedPDF)

        let report = try validator.verifyPDF(pdf)

        #expect(report.verdict == .error)
        #expect(report.signatures.isEmpty)
        #expect(report.steps.first?.status == .fail)
    }

    @Test
    func passesExternalTrustOptionsThroughFFI() throws {
        let validator = try SDTrustKit()
        let options = VerificationOptions(
            signerTrustAnchorsDer: [Data([0x01, 0x02, 0x03])],
            timestampCertificateSha256Pins: ["abcdef"]
        )

        let report = try validator.verifyPDF(Data("not a pdf".utf8), options: options)

        #expect(report.verdict == .error)
        #expect(report.standards.subIndication == .formatIssue)
    }

    @Test
    func passesRevocationCacheThroughFFI() throws {
        let validator = try SDTrustKit()
        let revocationOptions = RevocationOptions(
            nowUnixSeconds: 1_779_530_582,
            crlCacheEntries: [
                CrlCacheEntry(
                    url: "http://example.com/signers.crl",
                    validUntilUnixSeconds: 1_779_530_582,
                    der: Data([0x01, 0x02, 0x03])
                )
            ]
        )

        let report = try validator.verifyPDFIncludingRevocation(
            Data("not a pdf".utf8),
            revocationOptions: revocationOptions
        )

        #expect(report.verdict == .error)
        #expect(report.signatures.isEmpty)
    }

    @Test
    func decodesEveryRustStepKind() throws {
        let kinds = [
            "parsePDF",
            "signatureFieldResolution",
            "byteRangeCoverage",
            "byteRangeBounds",
            "documentModifiedAfterSigning",
            "cmsStructure",
            "padesBaselineRequirements",
            "signerInfoPresent",
            "messageDigestMatches",
            "messageDigestAttribute",
            "signerCertificatePresent",
            "signerCertificateValidity",
            "signerCertificateKeyUsage",
            "signerCertificateExtendedKeyUsage",
            "signatureVerifySignedAttributes",
            "signatureVerifyContent",
            "signerCertificateChain",
            "tsaTimestamp",
            "tsaMessageImprint",
            "tsaSignatureVerify",
            "tsaExtendedKeyUsage",
            "tsaCertificateChain",
            "documentTimestamp",
            "revocationSigner",
            "other",
        ]
        let steps = kinds
            .map { #"{"kind":"\#($0)","name":"step","status":"ok","detail":"decoded"}"# }
            .joined(separator: ",")
        let json = Data(
            """
            {
              "steps": [\(steps)],
              "signerName": null,
              "signerNames": [],
              "signingTime": null,
              "verdict": "valid",
              "signatures": [],
              "documentTimestamps": [],
              "standards": {
                "indication": "passed",
                "subIndication": "none",
                "diagnostic": null
              },
              "padesLevel": "baselineT",
              "preservation": {
                "level": "timestamped",
                "label": "Timestamped",
                "detail": "trusted time"
              }
            }
            """.utf8
        )

        let report = try JSONDecoder.rustReport.decode(ValidationReport.self, from: json)

        #expect(report.steps.count == kinds.count)
        #expect(report.padesLevel == .baselineT)
        #expect(report.preservation.level == .timestamped)
        #expect(report.preservation.label == "Timestamped")
        #expect(report.steps.map(\.kind).contains(.signatureFieldResolution))
        #expect(report.steps.map(\.kind).contains(.padesBaselineRequirements))
        #expect(report.steps.map(\.kind).contains(.signerCertificateValidity))
        #expect(report.steps.map(\.kind).contains(.signerCertificateKeyUsage))
        #expect(report.steps.map(\.kind).contains(.signerCertificateExtendedKeyUsage))
    }

    @Test
    func matchesRustCLIForCorpusPDF() throws {
        let paths = TestPaths()
        guard FileManager.default.fileExists(atPath: paths.corpusPDF.path),
              FileManager.default.fileExists(atPath: paths.rustCLI.path)
        else {
            return
        }

        let pdf = try Data(contentsOf: paths.corpusPDF)
        let wrapperReport = try SDTrustKit().verifyPDF(pdf)
        let cliReport = try runRustCLI(paths.rustCLI, pdf: paths.corpusPDF)

        #expect(wrapperReport == cliReport)
    }

    private func runRustCLI(_ cli: URL, pdf: URL) throws -> ValidationReport {
        let output = Pipe()
        let process = Process()
        process.executableURL = cli
        process.arguments = [pdf.path]
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        return try JSONDecoder.rustReport.decode(ValidationReport.self, from: data)
    }
}

private struct TestPaths {
    let repoRoot: URL
    let rustCLI: URL
    let corpusPDF: URL
    let dssOpenProtectedPDF: URL

    init(filePath: String = #filePath) {
        let packageRoot = URL(fileURLWithPath: filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let repoRoot = packageRoot
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        self.repoRoot = repoRoot
        self.rustCLI = repoRoot
            .appendingPathComponent("rust/sd_trust_kit/target/release/sd-trust-validate")
        self.corpusPDF = repoRoot
            .deletingLastPathComponent()
            .appendingPathComponent("CEISign/testpdfs/sources/0001.pdf")
        self.dssOpenProtectedPDF = repoRoot
            .appendingPathComponent("validation-corpus/eu-dss-fixtures/d9473b8efea72fd5754623fa92bb9311f2b005c5/resources/dss-cookbook/snippets/open_protected.pdf")
    }
}
