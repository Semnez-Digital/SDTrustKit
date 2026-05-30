from pathlib import Path
from time import perf_counter
import logging
from contextlib import redirect_stderr

from asn1crypto import pem, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
import pyhanko.version as pyhanko_version

logging.disable(logging.CRITICAL)
ROOT = Path('validation-corpus/combined-pdfs')
TRUST_ROOTS = [
    Path('rust/sd_trust_kit/tests/fixtures/pdf_model_gaps/root.cert.pem'),
    Path('rust/sd_trust_kit/tests/fixtures/pdf_model_gaps/tsa-root.cert.pem'),
]
ITERATIONS = 3
WARMUPS = 1

def load_roots():
    roots = []
    for cert_path in TRUST_ROOTS:
        data = cert_path.read_bytes()
        if pem.detect(data):
            _, _, data = pem.unarmor(data)
        roots.append(x509.Certificate.load(data))
    return roots

def clean(value):
    return str(value or '').replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')

def aggregate(statuses, error):
    if error:
        return 'Error'
    if not statuses:
        return 'NO_SIGNATURES'
    if all(s.get('bottom_line') for s in statuses):
        return 'Valid'
    if any(not s.get('intact', False) or not s.get('valid', False) for s in statuses):
        return 'Invalid'
    return 'Inconclusive'

def validate(path, roots):
    statuses = []
    error = ''
    try:
        with path.open('rb') as f, open('/dev/null', 'w') as devnull, redirect_stderr(devnull):
            reader = PdfFileReader(f)
            for embedded in list(reader.embedded_regular_signatures):
                signer_context = ValidationContext(trust_roots=roots, allow_fetching=False, revocation_mode='soft-fail')
                timestamp_context = ValidationContext(trust_roots=roots, allow_fetching=False, revocation_mode='soft-fail')
                status = validate_pdf_signature(
                    embedded,
                    signer_validation_context=signer_context,
                    ts_validation_context=timestamp_context,
                )
                statuses.append({
                    'summary': status.summary(),
                    'bottom_line': bool(getattr(status, 'bottom_line', False)),
                    'intact': bool(getattr(status, 'intact', False)),
                    'valid': bool(getattr(status, 'valid', False)),
                    'trusted': bool(getattr(status, 'trusted', False)),
                })
    except BaseException as exc:
        error = f'{type(exc).__name__}:{exc}'
    return statuses, error

def main():
    roots = load_roots()
    pdfs = sorted(p for p in ROOT.rglob('*') if p.is_file() and p.suffix.lower() == '.pdf')
    print('file\tbytes\twarmups\titerations\ttotal_ms\tavg_ms\tmin_ms\tmax_ms\taggregate\tsignature_count\tbottom_line_count\tsummaries\terror\tpyhanko_version')
    for path in pdfs:
        last_statuses = []
        last_error = ''
        for _ in range(WARMUPS):
            last_statuses, last_error = validate(path, roots)
        total = 0.0
        min_ms = float('inf')
        max_ms = 0.0
        for _ in range(ITERATIONS):
            start = perf_counter()
            last_statuses, last_error = validate(path, roots)
            elapsed = (perf_counter() - start) * 1000.0
            total += elapsed
            min_ms = min(min_ms, elapsed)
            max_ms = max(max_ms, elapsed)
        summaries = '|'.join(clean(s.get('summary')) for s in last_statuses)
        bottom_line_count = sum(1 for s in last_statuses if s.get('bottom_line'))
        print(
            f'{path.relative_to(ROOT)}\t{path.stat().st_size}\t{WARMUPS}\t{ITERATIONS}\t'
            f'{total:.3f}\t{(total / ITERATIONS):.3f}\t{min_ms:.3f}\t{max_ms:.3f}\t'
            f'{aggregate(last_statuses, last_error)}\t{len(last_statuses)}\t{bottom_line_count}\t'
            f'{clean(summaries)}\t{clean(last_error)}\t{pyhanko_version.__version__}'
        )

if __name__ == '__main__':
    main()
