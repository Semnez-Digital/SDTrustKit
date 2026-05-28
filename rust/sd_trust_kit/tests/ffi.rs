use serde_json::Value;
use std::ffi::{CStr, CString};

#[test]
fn ffi_verify_pdf_returns_report_json() {
    let pdf = b"not a pdf";
    let json = unsafe {
        ffi_string(sd_trust_kit::sd_trust_kit_verify_pdf_json(
            pdf.as_ptr(),
            pdf.len(),
        ))
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["verdict"], "error");
    assert_eq!(value["standards"]["indication"], "failed");
    assert_eq!(value["signatures"].as_array().unwrap().len(), 0);
}

#[test]
fn ffi_verify_unsigned_pdf_returns_no_signatures() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nstartxref\n0\n%%EOF\n";
    let json = unsafe {
        ffi_string(sd_trust_kit::sd_trust_kit_verify_pdf_json(
            pdf.as_ptr(),
            pdf.len(),
        ))
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["verdict"], "noSignatures");
    assert_eq!(value["signatures"].as_array().unwrap().len(), 0);
    assert_eq!(value["steps"][0]["status"], "ok");
}

#[test]
fn ffi_options_accept_external_trust_material() {
    let der = include_bytes!("fixtures/app_trust_anchors/b7a766f52218c8083e936f9ab085e97c67671ecd4fd3069b641c638072e44b1d-ro-cei-mai-root-ca.der");
    let options = CString::new(format!(
        r#"{{"signerTrustAnchorsDerBase64":["{}"]}}"#,
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der)
    ))
    .expect("options JSON CString");
    let pdf = b"not a pdf";

    let json = unsafe {
        ffi_string(sd_trust_kit::sd_trust_kit_verify_pdf_with_options_json(
            pdf.as_ptr(),
            pdf.len(),
            options.as_ptr(),
        ))
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["verdict"], "error");
    assert!(value.get("error").is_none());
}

#[test]
fn ffi_options_report_decode_errors_as_json() {
    let options = CString::new(r#"{"signerTrustAnchorsDerBase64":["@@not-base64@@"]}"#).unwrap();
    let pdf = b"not a pdf";

    let json = unsafe {
        ffi_string(sd_trust_kit::sd_trust_kit_verify_pdf_with_options_json(
            pdf.as_ptr(),
            pdf.len(),
            options.as_ptr(),
        ))
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["error"]["code"], "invalidBase64");
}

#[test]
fn ffi_revocation_options_accept_external_crl_cache_entries() {
    let revocation_options = CString::new(
        r#"{
            "nowUnixSeconds": 1779530582.0,
            "crlCacheEntries": [
                {
                    "url": "http://example.com/signers.crl",
                    "validUntilUnixSeconds": 1779530582.0,
                    "derBase64": "AQID"
                }
            ]
        }"#,
    )
    .expect("revocation options JSON CString");
    let pdf = b"not a pdf";

    let json = unsafe {
        ffi_string(
            sd_trust_kit::sd_trust_kit_verify_pdf_including_revocation_with_options_json(
                pdf.as_ptr(),
                pdf.len(),
                std::ptr::null(),
                revocation_options.as_ptr(),
            ),
        )
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["verdict"], "error");
    assert!(value.get("error").is_none());
}

#[test]
fn ffi_revocation_options_report_decode_errors_as_json() {
    let revocation_options = CString::new(
        r#"{
            "nowUnixSeconds": 1779530582.0,
            "crlCacheEntries": [
                {
                    "cacheKeySha256": "abc123",
                    "validUntilUnixSeconds": 1779530582.0,
                    "derBase64": "@@not-base64@@"
                }
            ]
        }"#,
    )
    .unwrap();
    let pdf = b"not a pdf";

    let json = unsafe {
        ffi_string(
            sd_trust_kit::sd_trust_kit_verify_pdf_including_revocation_with_options_json(
                pdf.as_ptr(),
                pdf.len(),
                std::ptr::null(),
                revocation_options.as_ptr(),
            ),
        )
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["error"]["code"], "invalidBase64");
}

#[test]
fn ffi_revocation_options_require_now_for_crl_cache_entries() {
    let revocation_options = CString::new(
        r#"{
            "crlCacheEntries": [
                {
                    "url": "https://example.com/signers.crl",
                    "validUntilUnixSeconds": 1779530582.0,
                    "derBase64": "AQID"
                }
            ]
        }"#,
    )
    .unwrap();
    let pdf = b"not a pdf";

    let json = unsafe {
        ffi_string(
            sd_trust_kit::sd_trust_kit_verify_pdf_including_revocation_with_options_json(
                pdf.as_ptr(),
                pdf.len(),
                std::ptr::null(),
                revocation_options.as_ptr(),
            ),
        )
    };
    let value: Value = serde_json::from_str(&json).expect("FFI JSON");

    assert_eq!(value["error"]["code"], "missingRevocationNow");
}

unsafe fn ffi_string(ptr: *mut std::os::raw::c_char) -> String {
    assert!(!ptr.is_null(), "FFI returned null string");
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("UTF-8 FFI string")
        .to_owned();
    unsafe {
        sd_trust_kit::sd_trust_kit_free_string(ptr);
    }
    value
}
