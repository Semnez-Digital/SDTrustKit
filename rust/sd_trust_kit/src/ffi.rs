use crate::{
    revocation::crl_cache_key_for_url, verify_pdf, verify_pdf_including_revocation_with_options,
    verify_pdf_with_options, CrlCache, CrlCacheEntry, RevocationOptions, TimedTrustAnchorSet,
    ValidationReport, VerificationOptions,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

const APPLE_REFERENCE_UNIX_OFFSET: f64 = 978_307_200.0;

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FfiVerificationOptions {
    signer_trust_anchors_der_base64: Vec<String>,
    signer_trust_anchor_sets: Vec<FfiTimedTrustAnchorSet>,
    timestamp_trust_anchors_der_base64: Vec<String>,
    timestamp_trust_anchor_sets: Vec<FfiTimedTrustAnchorSet>,
    timestamp_certificate_sha256_pins: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FfiTimedTrustAnchorSet {
    valid_from_unix_seconds: Option<f64>,
    valid_until_unix_seconds: Option<f64>,
    anchors_der_base64: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FfiRevocationOptions {
    now_unix_seconds: Option<f64>,
    crl_cache_entries: Vec<FfiCrlCacheEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FfiCrlCacheEntry {
    url: Option<String>,
    cache_key_sha256: Option<String>,
    valid_until_unix_seconds: Option<f64>,
    der_base64: Option<String>,
}

#[derive(Serialize)]
struct FfiError<'a> {
    error: FfiErrorBody<'a>,
}

#[derive(Serialize)]
struct FfiErrorBody<'a> {
    code: &'a str,
    message: String,
}

#[no_mangle]
/// Verify a PDF buffer and return an owned JSON C string.
///
/// # Safety
///
/// `pdf` must point to `pdf_len` readable bytes, unless `pdf_len` is zero and
/// `pdf` is null. The returned pointer must be released with
/// `sd_trust_kit_free_string`.
pub unsafe extern "C" fn sd_trust_kit_verify_pdf_json(pdf: *const u8, pdf_len: usize) -> *mut c_char {
    ffi_json_string(|| {
        let pdf = unsafe { raw_bytes(pdf, pdf_len, "pdf")? };
        serialize_report(&verify_pdf(pdf))
    })
}

#[no_mangle]
/// Verify a PDF buffer with JSON verification options and return an owned JSON C string.
///
/// # Safety
///
/// `pdf` must point to `pdf_len` readable bytes, unless `pdf_len` is zero and
/// `pdf` is null. `options_json`, when non-null, must point to a valid
/// NUL-terminated UTF-8 string. The returned pointer must be released with
/// `sd_trust_kit_free_string`.
pub unsafe extern "C" fn sd_trust_kit_verify_pdf_with_options_json(
    pdf: *const u8,
    pdf_len: usize,
    options_json: *const c_char,
) -> *mut c_char {
    ffi_json_string(|| {
        let pdf = unsafe { raw_bytes(pdf, pdf_len, "pdf")? };
        let options = unsafe { options_from_json(options_json)? };
        serialize_report(&verify_pdf_with_options(pdf, &options))
    })
}

#[no_mangle]
/// Verify a PDF buffer with JSON verification and revocation options.
///
/// # Safety
///
/// `pdf` must point to `pdf_len` readable bytes, unless `pdf_len` is zero and
/// `pdf` is null. JSON option pointers, when non-null, must point to valid
/// NUL-terminated UTF-8 strings. The returned pointer must be released with
/// `sd_trust_kit_free_string`.
pub unsafe extern "C" fn sd_trust_kit_verify_pdf_including_revocation_with_options_json(
    pdf: *const u8,
    pdf_len: usize,
    verification_options_json: *const c_char,
    revocation_options_json: *const c_char,
) -> *mut c_char {
    ffi_json_string(|| {
        let pdf = unsafe { raw_bytes(pdf, pdf_len, "pdf")? };
        let verification_options = unsafe { options_from_json(verification_options_json)? };
        let revocation_options = unsafe { revocation_options_from_json(revocation_options_json)? };
        serialize_report(&verify_pdf_including_revocation_with_options(
            pdf,
            &verification_options,
            &revocation_options,
        ))
    })
}

#[no_mangle]
/// Release a string returned by this library.
///
/// # Safety
///
/// `value` must be null or a pointer previously returned by one of this
/// library's JSON FFI functions that has not already been freed.
pub unsafe extern "C" fn sd_trust_kit_free_string(value: *mut c_char) {
    if !value.is_null() {
        unsafe {
            let _ = CString::from_raw(value);
        }
    }
}

fn ffi_json_string(work: impl FnOnce() -> Result<String, FfiFailure>) -> *mut c_char {
    let json = match catch_unwind(AssertUnwindSafe(work)) {
        Ok(Ok(json)) => json,
        Ok(Err(error)) => error_json(error.code, error.message),
        Err(_) => error_json("panic", "Rust PDF validation panicked.".to_owned()),
    };
    string_to_owned_c_ptr(json)
}

fn serialize_report(report: &ValidationReport) -> Result<String, FfiFailure> {
    serde_json::to_string(report).map_err(|error| {
        FfiFailure::new(
            "serializeReport",
            format!("Couldn't serialize validation report: {error}"),
        )
    })
}

unsafe fn raw_bytes<'a>(
    ptr: *const u8,
    len: usize,
    argument_name: &'static str,
) -> Result<&'a [u8], FfiFailure> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(FfiFailure::new(
                "invalidArgument",
                format!("{argument_name} pointer is null but length is {len}."),
            ))
        };
    }

    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

unsafe fn options_from_json(
    options_json: *const c_char,
) -> Result<VerificationOptions, FfiFailure> {
    if options_json.is_null() {
        return Ok(VerificationOptions::default());
    }

    let json = unsafe { CStr::from_ptr(options_json) }
        .to_str()
        .map_err(|error| {
            FfiFailure::new("invalidUtf8", format!("Options JSON is not UTF-8: {error}"))
        })?;
    let ffi_options: FfiVerificationOptions = serde_json::from_str(json).map_err(|error| {
        FfiFailure::new(
            "invalidOptionsJson",
            format!("Couldn't decode verification options JSON: {error}"),
        )
    })?;
    ffi_options.try_into()
}

unsafe fn revocation_options_from_json(
    revocation_options_json: *const c_char,
) -> Result<RevocationOptions, FfiFailure> {
    if revocation_options_json.is_null() {
        return Ok(RevocationOptions::default());
    }

    let json = unsafe { cstr_to_str(revocation_options_json, "Revocation options JSON")? };
    let ffi_options: FfiRevocationOptions = serde_json::from_str(json).map_err(|error| {
        FfiFailure::new(
            "invalidRevocationOptionsJson",
            format!("Couldn't decode revocation options JSON: {error}"),
        )
    })?;
    ffi_options.try_into()
}

unsafe fn cstr_to_str<'a>(
    value: *const c_char,
    argument_name: &str,
) -> Result<&'a str, FfiFailure> {
    unsafe { CStr::from_ptr(value) }.to_str().map_err(|error| {
        FfiFailure::new(
            "invalidUtf8",
            format!("{argument_name} is not UTF-8: {error}"),
        )
    })
}

impl TryFrom<FfiVerificationOptions> for VerificationOptions {
    type Error = FfiFailure;

    fn try_from(value: FfiVerificationOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            signer_trust_anchors: decode_base64_list(
                value.signer_trust_anchors_der_base64,
                "signerTrustAnchorsDerBase64",
            )?,
            signer_trust_anchor_sets: timed_anchor_sets(value.signer_trust_anchor_sets)?,
            timestamp_trust_anchors: decode_base64_list(
                value.timestamp_trust_anchors_der_base64,
                "timestampTrustAnchorsDerBase64",
            )?,
            timestamp_trust_anchor_sets: timed_anchor_sets(value.timestamp_trust_anchor_sets)?,
            timestamp_certificate_sha256_pins: value.timestamp_certificate_sha256_pins,
        })
    }
}

impl TryFrom<FfiRevocationOptions> for RevocationOptions {
    type Error = FfiFailure;

    fn try_from(value: FfiRevocationOptions) -> Result<Self, Self::Error> {
        let has_crl_entries = !value.crl_cache_entries.is_empty();
        let now_unix_seconds = match value.now_unix_seconds {
            Some(now) => now,
            None if has_crl_entries => {
                return Err(FfiFailure::new(
                    "missingRevocationNow",
                    "Revocation options with CRL cache entries require nowUnixSeconds.",
                ))
            }
            None => 0.0,
        };

        Ok(Self {
            crl_cache: CrlCache {
                entries: crl_cache_entries(value.crl_cache_entries)?,
            },
            now_unix_seconds,
        })
    }
}

fn crl_cache_entries(entries: Vec<FfiCrlCacheEntry>) -> Result<Vec<CrlCacheEntry>, FfiFailure> {
    let mut out: Vec<CrlCacheEntry> = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| crl_cache_entry(index, entry))
        .collect::<Result<_, _>>()?;
    out.sort_by(|a, b| a.cache_key_sha256.cmp(&b.cache_key_sha256));
    Ok(out)
}

fn crl_cache_entry(index: usize, entry: FfiCrlCacheEntry) -> Result<CrlCacheEntry, FfiFailure> {
    let cache_key_sha256 = match (entry.cache_key_sha256, entry.url) {
        (Some(cache_key), _) => cache_key.to_ascii_lowercase(),
        (None, Some(url)) => crl_cache_key_for_url(&url).ok_or_else(|| {
            FfiFailure::new(
                "invalidCrlUrl",
                format!("crlCacheEntries[{index}].url is not an HTTP(S) URL."),
            )
        })?,
        (None, None) => {
            return Err(FfiFailure::new(
                "missingCrlCacheKey",
                format!("crlCacheEntries[{index}] needs url or cacheKeySha256."),
            ))
        }
    };
    let valid_until_unix_seconds = entry.valid_until_unix_seconds.ok_or_else(|| {
        FfiFailure::new(
            "missingCrlValidUntil",
            format!("crlCacheEntries[{index}].validUntilUnixSeconds is required."),
        )
    })?;
    let der_base64 = entry.der_base64.ok_or_else(|| {
        FfiFailure::new(
            "missingCrlDer",
            format!("crlCacheEntries[{index}].derBase64 is required."),
        )
    })?;

    Ok(CrlCacheEntry {
        cache_key_sha256,
        valid_until: valid_until_unix_seconds - APPLE_REFERENCE_UNIX_OFFSET,
        der: decode_base64(der_base64, &format!("crlCacheEntries[{index}].derBase64"))?,
    })
}

fn timed_anchor_sets(
    sets: Vec<FfiTimedTrustAnchorSet>,
) -> Result<Vec<TimedTrustAnchorSet>, FfiFailure> {
    sets.into_iter()
        .enumerate()
        .map(|(index, set)| {
            Ok(TimedTrustAnchorSet {
                valid_from_unix_seconds: set.valid_from_unix_seconds,
                valid_until_unix_seconds: set.valid_until_unix_seconds,
                anchors: decode_base64_list(
                    set.anchors_der_base64,
                    &format!("anchorsDerBase64 at index {index}"),
                )?,
            })
        })
        .collect()
}

fn decode_base64_list(values: Vec<String>, field_name: &str) -> Result<Vec<Vec<u8>>, FfiFailure> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|error| {
                    FfiFailure::new(
                        "invalidBase64",
                        format!("{field_name}[{index}] is not valid base64 DER: {error}"),
                    )
                })
        })
        .collect()
}

fn decode_base64(value: String, field_name: &str) -> Result<Vec<u8>, FfiFailure> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| {
            FfiFailure::new(
                "invalidBase64",
                format!("{field_name} is not valid base64 DER: {error}"),
            )
        })
}

fn error_json(code: &'static str, message: String) -> String {
    serde_json::to_string(&FfiError {
        error: FfiErrorBody { code, message },
    })
    .unwrap_or_else(|_| {
        "{\"error\":{\"code\":\"serializeError\",\"message\":\"Couldn't serialize FFI error.\"}}"
            .to_owned()
    })
}

fn string_to_owned_c_ptr(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => value.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

struct FfiFailure {
    code: &'static str,
    message: String,
}

impl FfiFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
