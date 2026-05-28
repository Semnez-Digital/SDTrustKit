use std::fs;
use std::path::{Path, PathBuf};

use sd_trust_kit::{ValidationSubIndication, Verdict};

#[test]
fn ignores_orphan_signature_dictionary_after_final_eof() {
    let Some(root) = signed_pdfs_root() else {
        eprintln!("skipping signed_pdfs-backed test; set SIGNED_PDFS_ROOT to enable");
        return;
    };
    let path = root.join("sources/pyhanko/sig-no-signed-attrs.pdf");
    let base = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let base_report = sd_trust_kit::verify_pdf(&base);

    let mut spoofed = base.clone();
    append_orphan_signature_dictionary(&mut spoofed, &base);
    let spoofed_report = sd_trust_kit::verify_pdf(&spoofed);

    assert_eq!(base_report.signatures.len(), 1);
    assert_eq!(
        spoofed_report.signatures.len(),
        base_report.signatures.len()
    );
    assert!(
        spoofed_report
            .signatures
            .iter()
            .all(|signature| signature.byte_range != vec![0, 0, 0, 0]),
        "post-EOF orphan signature dictionary was treated as a PDF signature"
    );
}

#[test]
fn rejects_signature_dictionary_changed_in_later_revision() {
    let Some(root) = signed_pdfs_root() else {
        eprintln!("skipping signed_pdfs-backed test; set SIGNED_PDFS_ROOT to enable");
        return;
    };
    let path = root.join("sources/pyhanko/sig-no-signed-attrs.pdf");
    let base = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let mut spoofed = base.clone();
    append_changed_signature_dictionary_revision(&mut spoofed, &base);
    let report = sd_trust_kit::verify_pdf(&spoofed);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::DocumentModifiedAfterSigning
    );
    assert!(report.steps.iter().any(|step| {
        step.name == "Document modified after signing"
            && step.detail == "Signature dictionary changed after the signed revision"
    }));
}

#[test]
fn rejects_validation_data_tail_that_redefines_existing_object() {
    let Some(root) = signed_pdfs_root() else {
        eprintln!("skipping signed_pdfs-backed test; set SIGNED_PDFS_ROOT to enable");
        return;
    };
    let path = root.join("sources/pyhanko/sig-no-signed-attrs.pdf");
    let base = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let mut spoofed = base.clone();
    append_spoofed_validation_data_tail(&mut spoofed, &base);
    let report = sd_trust_kit::verify_pdf(&spoofed);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::DocumentModifiedAfterSigning
    );
    assert!(report.steps.iter().any(|step| {
        step.name == "Document modified after signing"
            && step.detail == "Later validation-data revision changed an existing PDF object"
    }));
}

#[test]
fn rejects_signature_field_value_changed_in_later_revision() {
    let Some(root) = signed_pdfs_root() else {
        eprintln!("skipping signed_pdfs-backed test; set SIGNED_PDFS_ROOT to enable");
        return;
    };
    let path = root.join("sources/pyhanko/sig-no-signed-attrs.pdf");
    let base = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));

    let mut spoofed = base.clone();
    append_changed_signature_field_value_revision(&mut spoofed, &base);
    let report = sd_trust_kit::verify_pdf(&spoofed);

    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.standards.sub_indication,
        ValidationSubIndication::DocumentModifiedAfterSigning
    );
    assert!(report.steps.iter().any(|step| {
        step.name == "Document modified after signing"
            && step.detail == "Signature field reference changed after the signed revision"
    }));
}

fn append_orphan_signature_dictionary(pdf: &mut Vec<u8>, source: &[u8]) {
    let contents_hex = first_signature_contents_hex(source);
    pdf.extend_from_slice(
        format!(
            "\n9999 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 0 0 0] /Contents <{}> >>\nendobj\n",
            contents_hex
        )
        .as_bytes(),
    );
}

fn append_spoofed_validation_data_tail(pdf: &mut Vec<u8>, source: &[u8]) {
    let (object_number, generation) = first_indirect_object_id(source);
    pdf.extend_from_slice(
        format!(
            "\n{object_number} {generation} obj\n<< /Stage4Spoof true >>\nendobj\n9998 0 obj\n<< /Type /DSS /Certs [{object_number} {generation} R] >>\nendobj\n%%EOF\n"
        )
        .as_bytes(),
    );
}

fn append_changed_signature_field_value_revision(pdf: &mut Vec<u8>, source: &[u8]) {
    let (signature_object_number, signature_generation, _) = first_signature_object_body(source);
    let (field_object_number, field_generation, field_body) =
        first_signature_field_object_body(source, signature_object_number, signature_generation);
    let original_value = format!("/V {signature_object_number} {signature_generation} R");
    let changed_body = field_body.replace(&original_value, "/V 9997 0 R");
    assert_ne!(changed_body, field_body, "fixture field has signature /V");
    pdf.extend_from_slice(
        format!(
            "\n9997 0 obj\n<< /Type /Sig /Reason (field spoof target) >>\nendobj\n{field_object_number} {field_generation} obj\n{changed_body}\nendobj\n%%EOF\n"
        )
        .as_bytes(),
    );
}

fn append_changed_signature_dictionary_revision(pdf: &mut Vec<u8>, source: &[u8]) {
    let (object_number, generation, mut body) = first_signature_object_body(source);
    let insert_at = body
        .rfind(">>")
        .expect("signature object has dictionary end");
    body.insert_str(insert_at, " /Reason (spoofed after signing)");
    pdf.extend_from_slice(
        format!("\n{object_number} {generation} obj\n{body}\nendobj\n%%EOF\n").as_bytes(),
    );
}

fn first_indirect_object_id(pdf: &[u8]) -> (usize, usize) {
    let obj_marker = b" obj";
    let marker_start = pdf
        .windows(obj_marker.len())
        .position(|window| window == obj_marker)
        .expect("fixture has an indirect object");
    object_id_before_obj_marker(pdf, marker_start)
}

fn first_signature_field_object_body(
    pdf: &[u8],
    signature_object_number: usize,
    signature_generation: usize,
) -> (usize, usize, String) {
    let reference = format!("/V {signature_object_number} {signature_generation} R");
    let reference_start = String::from_utf8_lossy(pdf)
        .find(&reference)
        .expect("fixture has a field pointing at the signature object");
    let obj_marker = b" obj";
    let obj_marker_start = pdf[..reference_start]
        .windows(obj_marker.len())
        .rposition(|window| window == obj_marker)
        .expect("fixture signature field is an indirect object");
    let (object_number, generation) = object_id_before_obj_marker(pdf, obj_marker_start);
    let object_body_start = obj_marker_start + obj_marker.len();
    let endobj = b"endobj";
    let object_body_end = pdf[reference_start..]
        .windows(endobj.len())
        .position(|window| window == endobj)
        .map(|offset| reference_start + offset)
        .expect("fixture signature field object has endobj");
    (
        object_number,
        generation,
        String::from_utf8(pdf[object_body_start..object_body_end].to_vec())
            .expect("fixture signature field object is ASCII"),
    )
}

fn first_signature_object_body(pdf: &[u8]) -> (usize, usize, String) {
    let byte_range = b"/ByteRange";
    let byte_range_start = pdf
        .windows(byte_range.len())
        .position(|window| window == byte_range)
        .expect("fixture has /ByteRange");
    let obj_marker = b" obj";
    let obj_marker_start = pdf[..byte_range_start]
        .windows(obj_marker.len())
        .rposition(|window| window == obj_marker)
        .expect("fixture signature is an indirect object");
    let (object_number, generation) = object_id_before_obj_marker(pdf, obj_marker_start);
    let object_body_start = obj_marker_start + obj_marker.len();
    let endobj = b"endobj";
    let object_body_end = pdf[byte_range_start..]
        .windows(endobj.len())
        .position(|window| window == endobj)
        .map(|offset| byte_range_start + offset)
        .expect("fixture signature object has endobj");
    (
        object_number,
        generation,
        String::from_utf8(pdf[object_body_start..object_body_end].to_vec())
            .expect("fixture signature object is ASCII"),
    )
}

fn object_id_before_obj_marker(pdf: &[u8], marker_start: usize) -> (usize, usize) {
    let mut i = marker_start;
    while i > 0 && pdf[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let generation_end = i;
    while i > 0 && pdf[i - 1].is_ascii_digit() {
        i -= 1;
    }
    let generation = std::str::from_utf8(&pdf[i..generation_end])
        .expect("generation is ASCII")
        .parse()
        .expect("generation is numeric");
    while i > 0 && pdf[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let number_end = i;
    while i > 0 && pdf[i - 1].is_ascii_digit() {
        i -= 1;
    }
    let object_number = std::str::from_utf8(&pdf[i..number_end])
        .expect("object number is ASCII")
        .parse()
        .expect("object number is numeric");
    (object_number, generation)
}

fn first_signature_contents_hex(pdf: &[u8]) -> String {
    let contents = b"/Contents";
    let byte_range = b"/ByteRange";
    let byte_range_start = pdf
        .windows(byte_range.len())
        .position(|window| window == byte_range)
        .expect("fixture has /ByteRange");
    let contents_start = pdf[..byte_range_start]
        .windows(contents.len())
        .rposition(|window| window == contents)
        .expect("fixture has signature /Contents");
    let mut i = contents_start + contents.len();
    while i < pdf.len() && pdf[i].is_ascii_whitespace() {
        i += 1;
    }
    assert_eq!(pdf.get(i), Some(&b'<'));
    i += 1;
    let hex_start = i;
    while i < pdf.len() && pdf[i] != b'>' {
        i += 1;
    }
    String::from_utf8(pdf[hex_start..i].to_vec()).expect("signature contents are hex")
}

fn signed_pdfs_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SIGNED_PDFS_ROOT") {
        return Some(PathBuf::from(path));
    }
    let sibling = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("crate should live under rust/sd_trust_kit")
        .join("signed_pdfs");
    sibling.is_dir().then_some(sibling)
}
