use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn main() {
    let dir = PathBuf::from(env::args().nth(1).expect("fixture dir"));
    let iterations: usize = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let warmups: usize = env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut pdfs = Vec::new();
    collect_pdfs(&dir, &mut pdfs);
    pdfs.sort();
    println!("file\tbytes\twarmups\titerations\ttotal_ms\tavg_ms\tmin_ms\tmax_ms\tverdict\tsignature_count\tpades_level\tpreservation_label\tstandards_indication\tstandards_sub_indication");
    for path in pdfs {
        let data = fs::read(&path).unwrap();
        let mut verdict = String::new();
        let mut signature_count = 0usize;
        let mut pades_level = String::new();
        let mut preservation_label = String::new();
        let mut standards_indication = String::new();
        let mut standards_sub_indication = String::new();
        for _ in 0..warmups {
            let report = sd_trust_kit::verify_pdf(&data);
            capture(&report, &mut verdict, &mut signature_count, &mut pades_level, &mut preservation_label, &mut standards_indication, &mut standards_sub_indication);
        }
        let mut total = 0.0;
        let mut min = f64::MAX;
        let mut max = 0.0;
        for _ in 0..iterations {
            let start = Instant::now();
            let report = sd_trust_kit::verify_pdf(&data);
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            capture(&report, &mut verdict, &mut signature_count, &mut pades_level, &mut preservation_label, &mut standards_indication, &mut standards_sub_indication);
            total += elapsed;
            if elapsed < min { min = elapsed; }
            if elapsed > max { max = elapsed; }
        }
        println!("{}\t{}\t{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{}\t{}\t{}\t{}\t{}\t{}",
            path.strip_prefix(&dir).unwrap_or(&path).to_string_lossy(), data.len(), warmups, iterations,
            total, total / iterations as f64, min, max, clean(&verdict), signature_count, clean(&pades_level), clean(&preservation_label), clean(&standards_indication), clean(&standards_sub_indication));
    }
}

fn capture(
    report: &sd_trust_kit::ValidationReport,
    verdict: &mut String,
    signature_count: &mut usize,
    pades_level: &mut String,
    preservation_label: &mut String,
    standards_indication: &mut String,
    standards_sub_indication: &mut String,
) {
    *verdict = format!("{:?}", report.verdict);
    *signature_count = report.signatures.len();
    *pades_level = format!("{:?}", report.pades_level);
    *preservation_label = report.preservation.label.clone();
    *standards_indication = format!("{:?}", report.standards.indication);
    *standards_sub_indication = format!("{:?}", report.standards.sub_indication);
}

fn collect_pdfs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_pdfs(&path, out);
        } else if path.extension().map(|e| e.eq_ignore_ascii_case("pdf")).unwrap_or(false) {
            out.push(path);
        }
    }
}

fn clean(value: &str) -> String {
    value.replace('\t', " ").replace('\n', " ").replace('\r', " ")
}
