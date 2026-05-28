use std::fs;
use std::path::Path;

use serde_json::Value;

#[test]
fn pdf_model_gap_fixtures_have_dss_failure_evidence() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf_model_gaps");
    let summary_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pdf_model_gaps_dss_reports/summary.json");
    let summary: Value = serde_json::from_slice(&fs::read(&summary_path).unwrap()).unwrap();
    let cases = summary.as_array().expect("summary is an array");
    assert!(!cases.is_empty(), "DSS summary contains cases");

    for case in cases {
        let file = case["file"].as_str().expect("case has file");
        assert!(fixture_root.join(file).is_file(), "fixture {file} exists");
        let primary = &case["primary"];
        if file == "control-valid.pdf" {
            assert_ne!(
                primary["indication"].as_str(),
                Some("TOTAL_FAILED"),
                "control fixture must not be the malformed oracle"
            );
            continue;
        }
        assert_eq!(
            primary["indication"].as_str(),
            Some("TOTAL_FAILED"),
            "{file} should be rejected by EU-DSS"
        );
        assert_eq!(
            primary["subIndication"].as_str(),
            Some("FORMAT_FAILURE"),
            "{file} should be a format-level malformed PDF/signature fixture"
        );
    }
}
