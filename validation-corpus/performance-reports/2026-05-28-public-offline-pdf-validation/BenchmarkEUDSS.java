import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.InputStream;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class BenchmarkEUDSS {
  public static void main(String[] args) throws Exception {
    Path dir = Paths.get(args[0]).toAbsolutePath();
    int iterations = args.length > 1 ? Integer.parseInt(args[1]) : 3;
    int warmups = args.length > 2 ? Integer.parseInt(args[2]) : 1;
    CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    Path repoRoot = dir.getParent() != null && dir.getParent().getParent() != null
      ? dir.getParent().getParent()
      : Paths.get(".").toAbsolutePath();
    Path localTrustDir = args.length > 3
      ? Paths.get(args[3]).toAbsolutePath()
      : repoRoot.resolve("rust/sd_trust_kit/tests/fixtures/pdf_model_gaps");
    for (String name : new String[]{"root.cert.pem", "tsa-root.cert.pem"}) {
      try (InputStream in = Files.newInputStream(localTrustDir.resolve(name))) {
        trust.addCertificate(new CertificateToken((X509Certificate) factory.generateCertificate(in)));
      }
    }
    CertificateVerifier verifier = new CommonCertificateVerifier();
    verifier.setTrustedCertSources(trust);
    verifier.setCheckRevocationForUntrustedChains(false);
    IgnoreDataLoader offlineLoader = new IgnoreDataLoader();
    verifier.setAIASource(new DefaultAIASource(offlineLoader));
    verifier.setCrlSource(new OnlineCRLSource(offlineLoader));
    verifier.setOcspSource(new OnlineOCSPSource(offlineLoader));

    ArrayList<Path> pdfs = new ArrayList<>();
    try (java.util.stream.Stream<Path> stream = Files.walk(dir)) {
      stream.filter(Files::isRegularFile)
        .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".pdf"))
        .forEach(pdfs::add);
    }
    Collections.sort(pdfs);
    System.out.println("file\tbytes\twarmups\titerations\ttotal_ms\tavg_ms\tmin_ms\tmax_ms\tdss_aggregate\tdss_signature_count\tdss_valid_signature_count\tdss_indications\tdss_subindications\tdss_valid_flags\tdss_error");
    for (Path pdf : pdfs) {
      DssResult last = null;
      for (int i = 0; i < warmups; i++) last = validateAndSummarize(pdf, verifier);
      double total = 0.0;
      double min = Double.MAX_VALUE;
      double max = 0.0;
      for (int i = 0; i < iterations; i++) {
        long start = System.nanoTime();
        last = validateAndSummarize(pdf, verifier);
        double elapsed = (System.nanoTime() - start) / 1_000_000.0;
        total += elapsed;
        if (elapsed < min) min = elapsed;
        if (elapsed > max) max = elapsed;
      }
      System.out.printf(Locale.US, "%s\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\t%s\t%d\t%d\t%s\t%s\t%s\t%s%n",
        dir.relativize(pdf).toString(), Files.size(pdf), warmups, iterations,
        total, total / iterations, min, max,
        clean(last.aggregate), last.signatureCount, last.validSignatureCount,
        clean(String.join("|", last.indications)), clean(String.join("|", last.subIndications)), clean(String.join("|", last.validFlags)), clean(last.error));
    }
  }

  private static DssResult validateAndSummarize(Path pdf, CertificateVerifier verifier) {
    DssResult result = new DssResult();
    try {
      DSSDocument document = new FileDocument(pdf.toFile());
      SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
      validator.setCertificateVerifier(verifier);
      Reports reports = validator.validateDocument();
      SimpleReport simple = reports.getSimpleReport();
      List<String> ids = simple.getSignatureIdList();
      result.signatureCount = ids.size();
      result.validSignatureCount = simple.getValidSignaturesCount();
      boolean anyFailed = false;
      boolean anyIndeterminate = false;
      boolean allValid = !ids.isEmpty();
      for (String id : ids) {
        Indication indication = simple.getIndication(id);
        SubIndication subIndication = simple.getSubIndication(id);
        boolean valid = simple.isValid(id);
        String indicationName = indication == null ? "" : indication.name();
        result.indications.add(indicationName);
        result.subIndications.add(subIndication == null ? "" : subIndication.name());
        result.validFlags.add(Boolean.toString(valid));
        allValid &= valid;
        if (indicationName.contains("FAILED")) anyFailed = true;
        if (indicationName.contains("INDETERMINATE")) anyIndeterminate = true;
      }
      if (ids.isEmpty()) result.aggregate = "NO_SIGNATURES";
      else if (allValid) result.aggregate = "Valid";
      else if (anyFailed) result.aggregate = "Invalid";
      else if (anyIndeterminate) result.aggregate = "Inconclusive";
      else result.aggregate = "Unknown";
    } catch (Throwable t) {
      result.aggregate = "Error";
      result.error = t.getClass().getSimpleName() + ":" + nullToEmpty(t.getMessage()).replace('\n', ' ').replace('\r', ' ');
    }
    return result;
  }

  private static String clean(String value) {
    return nullToEmpty(value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
  }

  private static String nullToEmpty(String value) {
    return value == null ? "" : value;
  }

  static class DssResult {
    String aggregate = "";
    int signatureCount = 0;
    int validSignatureCount = 0;
    ArrayList<String> indications = new ArrayList<>();
    ArrayList<String> subIndications = new ArrayList<>();
    ArrayList<String> validFlags = new ArrayList<>();
    String error = "";
  }
}
