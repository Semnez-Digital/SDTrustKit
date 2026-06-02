use crate::ffi::{
    sd_trust_kit_free_string, sd_trust_kit_verify_pdf_including_revocation_with_options_json,
    sd_trust_kit_verify_pdf_json, sd_trust_kit_verify_pdf_with_options_json,
};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "system" fn Java_com_sdtrustkit_SDTrustKitNative_verifyPdfJson(
    mut env: JNIEnv,
    _class: JClass,
    pdf: JByteArray,
) -> jstring {
    jni_json_string(&mut env, |env| {
        let pdf = env
            .convert_byte_array(pdf)
            .map_err(|error| format!("Could not read PDF byte array: {error}"))?;
        let ptr = unsafe { sd_trust_kit_verify_pdf_json(pdf.as_ptr(), pdf.len()) };
        owned_json_from_ffi(ptr)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sdtrustkit_SDTrustKitNative_verifyPdfWithOptionsJson(
    mut env: JNIEnv,
    _class: JClass,
    pdf: JByteArray,
    options_json: JString,
) -> jstring {
    jni_json_string(&mut env, |env| {
        let pdf = env
            .convert_byte_array(pdf)
            .map_err(|error| format!("Could not read PDF byte array: {error}"))?;
        let options_json = jstring_to_cstring(env, options_json)?;
        let ptr = unsafe {
            sd_trust_kit_verify_pdf_with_options_json(
                pdf.as_ptr(),
                pdf.len(),
                options_json
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
            )
        };
        owned_json_from_ffi(ptr)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sdtrustkit_SDTrustKitNative_verifyPdfIncludingRevocationJson(
    mut env: JNIEnv,
    _class: JClass,
    pdf: JByteArray,
    verification_options_json: JString,
    revocation_options_json: JString,
) -> jstring {
    jni_json_string(&mut env, |env| {
        let pdf = env
            .convert_byte_array(pdf)
            .map_err(|error| format!("Could not read PDF byte array: {error}"))?;
        let verification_options_json = jstring_to_cstring(env, verification_options_json)?;
        let revocation_options_json = jstring_to_cstring(env, revocation_options_json)?;
        let ptr = unsafe {
            sd_trust_kit_verify_pdf_including_revocation_with_options_json(
                pdf.as_ptr(),
                pdf.len(),
                verification_options_json
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                revocation_options_json
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
            )
        };
        owned_json_from_ffi(ptr)
    })
}

fn jni_json_string(
    env: &mut JNIEnv,
    work: impl FnOnce(&mut JNIEnv) -> Result<String, String>,
) -> jstring {
    let json = work(env).unwrap_or_else(|message| error_json("jniBridge", message));
    env.new_string(json)
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn jstring_to_cstring(env: &mut JNIEnv, value: JString) -> Result<Option<CString>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let value: String = env
        .get_string(&value)
        .map_err(|error| format!("Could not read JSON string: {error}"))?
        .into();
    CString::new(value)
        .map(Some)
        .map_err(|_| "JSON string contained an interior NUL byte".to_owned())
}

fn owned_json_from_ffi(ptr: *mut c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("Rust validation returned a null JSON pointer".to_owned());
    }
    let json = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
    unsafe {
        sd_trust_kit_free_string(ptr);
    }
    Ok(json)
}

fn error_json(code: &str, message: String) -> String {
    serde_json::json!({
        "error": {
            "code": code,
            "message": message
        }
    })
    .to_string()
}
