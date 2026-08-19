//! WebAssembly bindings for [`verusid_cmm_encrypt`].
//!
//! Exposes a single JS-callable function, `encryptPublicDecrypt`, that wraps
//! [`verusid_cmm_encrypt::encrypt_public_decrypt`]. Randomness is sourced from
//! `rand_core::OsRng`, which on `wasm32-unknown-unknown` routes through the
//! Web Crypto API (browser) or `node:crypto` (Node) via `getrandom`'s `js`
//! feature.
//!
//! # JS shape
//!
//! ```js
//! import { encryptPublicDecrypt } from "verusid-cmm-encrypt-wasm";
//!
//! const result = encryptPublicDecrypt({
//!   plaintext,             // Uint8Array
//!   outerVdxfKey,          // Uint8Array, exactly 20 bytes (LE from getvdxfid)
//!   systemId,              // Uint8Array, exactly 20 bytes (LE ASSETCHAINS_CHAINID)
//!   label,                 // string | null (optional)
//!   mimeType,              // string | null (optional)
//!   dataDepositVoutIndex,  // number, u32 — index of the first deposit output
//!   signature,             // Uint8Array | null (optional) — caller-supplied
//!                          //   signature attached as a second cmm descriptor
//! });
//! // result: {
//! //   cmmEntry: { vdxfKey: Uint8Array, value: Uint8Array },
//! //   dataDepositOutputScripts: Uint8Array[],   // 1 element normally,
//! //                                             // N when the payload
//! //                                             // triggers BreakApart
//! //   publishedIvk: Uint8Array,
//! //   outerEpk: Uint8Array,
//! //   ephemeralDiversifier: Uint8Array,
//! //   ephemeralPkD: Uint8Array,
//! // }
//! ```
//!
//! TypeScript users get typed request/result interfaces auto-generated into
//! the wasm-pack output — see the `typescript_custom_section` below.

use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_core::OsRng;
use verusid_cmm_encrypt::{
    encrypt_public_decrypt, EncryptError, EncryptRequest, EncryptResult,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[wasm_bindgen(typescript_custom_section)]
const TS_INTERFACES: &'static str = r#"
export interface EncryptPublicDecryptRequest {
    plaintext: Uint8Array;
    outerVdxfKey: Uint8Array;
    systemId: Uint8Array;
    label?: string | null;
    mimeType?: string | null;
    dataDepositVoutIndex: number;
    signature?: Uint8Array | null;
}

export interface CmmEntry {
    vdxfKey: Uint8Array;
    value: Uint8Array;
}

export interface EncryptPublicDecryptResult {
    cmmEntry: CmmEntry;
    dataDepositOutputScripts: Uint8Array[];
    publishedIvk: Uint8Array;
    outerEpk: Uint8Array;
    ephemeralDiversifier: Uint8Array;
    ephemeralPkD: Uint8Array;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "EncryptPublicDecryptRequest")]
    pub type JsEncryptRequest;
    #[wasm_bindgen(typescript_type = "EncryptPublicDecryptResult")]
    pub type JsEncryptResult;
}

/// Encrypt `request.plaintext` into a `flags:13` public-decrypt cmm entry and
/// its accompanying `EVAL_NOTARY_EVIDENCE` data-deposit output(s).
///
/// See the module-level docs for the JS request/response shape. Errors surface
/// as JavaScript `Error` instances with a message identifying the failing
/// input field or composed layer.
#[wasm_bindgen(js_name = encryptPublicDecrypt)]
pub fn encrypt_public_decrypt_js(request: JsEncryptRequest) -> Result<JsEncryptResult, JsError> {
    let request = JsValue::from(request);

    let plaintext = read_uint8array(&request, "plaintext")?;
    let outer_vdxf_key = read_uint8array_of_len(&request, "outerVdxfKey", 20)?;
    let system_id = read_uint8array_of_len(&request, "systemId", 20)?;
    let label = read_optional_string(&request, "label")?;
    let mime_type = read_optional_string(&request, "mimeType")?;
    let data_deposit_vout_index = read_u32(&request, "dataDepositVoutIndex")?;
    let signature = read_optional_uint8array(&request, "signature")?;

    let plaintext_bytes = plaintext.to_vec();
    let signature_bytes = signature.map(|s| s.to_vec());

    let core_req = EncryptRequest {
        plaintext: &plaintext_bytes,
        outer_vdxf_key,
        system_id,
        label: label.as_deref(),
        mime_type: mime_type.as_deref(),
        data_deposit_vout_index,
        signature: signature_bytes.as_deref(),
    };

    let mut rng = OsRng;
    let result =
        encrypt_public_decrypt(&core_req, &mut rng).map_err(map_encrypt_error)?;

    let js_value = build_result_object(&result)
        .map_err(|_| JsError::new("failed to construct result object"))?;
    Ok(js_value.unchecked_into::<JsEncryptResult>())
}

// --- Field readers ---------------------------------------------------------

fn read_field(obj: &JsValue, field: &str) -> Result<JsValue, JsError> {
    Reflect::get(obj, &JsValue::from_str(field))
        .map_err(|_| JsError::new(&format!("request must be an object with a {field} field")))
}

fn read_uint8array(obj: &JsValue, field: &str) -> Result<Uint8Array, JsError> {
    let val = read_field(obj, field)?;
    if val.is_undefined() || val.is_null() {
        return Err(JsError::new(&format!("{field} is required (Uint8Array)")));
    }
    val.dyn_into::<Uint8Array>()
        .map_err(|_| JsError::new(&format!("{field} must be a Uint8Array")))
}

fn read_uint8array_of_len(obj: &JsValue, field: &str, expected: usize) -> Result<[u8; 20], JsError> {
    let arr = read_uint8array(obj, field)?;
    let len = arr.length() as usize;
    if len != expected {
        return Err(JsError::new(&format!(
            "{field} must be exactly {expected} bytes, got {len}"
        )));
    }
    // The current callers only need 20-byte outputs; keeping the fixed-size
    // return type avoids a heap allocation and a slice-length check downstream.
    assert_eq!(expected, 20, "read_uint8array_of_len currently only supports 20-byte targets");
    let mut out = [0u8; 20];
    arr.copy_to(&mut out);
    Ok(out)
}

fn read_optional_uint8array(obj: &JsValue, field: &str) -> Result<Option<Uint8Array>, JsError> {
    let val = read_field(obj, field)?;
    if val.is_undefined() || val.is_null() {
        return Ok(None);
    }
    Ok(Some(val.dyn_into::<Uint8Array>().map_err(|_| {
        JsError::new(&format!("{field} must be a Uint8Array (or null/undefined)"))
    })?))
}

fn read_optional_string(obj: &JsValue, field: &str) -> Result<Option<String>, JsError> {
    let val = read_field(obj, field)?;
    if val.is_undefined() || val.is_null() {
        return Ok(None);
    }
    val.as_string()
        .map(Some)
        .ok_or_else(|| JsError::new(&format!("{field} must be a string (or null/undefined)")))
}

fn read_u32(obj: &JsValue, field: &str) -> Result<u32, JsError> {
    let val = read_field(obj, field)?;
    if val.is_undefined() || val.is_null() {
        return Err(JsError::new(&format!("{field} is required (number)")));
    }
    let n = val
        .as_f64()
        .ok_or_else(|| JsError::new(&format!("{field} must be a number")))?;
    if !n.is_finite() || n < 0.0 || n > f64::from(u32::MAX) || n.fract() != 0.0 {
        return Err(JsError::new(&format!(
            "{field} must be a non-negative integer that fits in u32"
        )));
    }
    Ok(n as u32)
}

// --- Result builders -------------------------------------------------------

fn map_encrypt_error(err: EncryptError) -> JsError {
    match err {
        EncryptError::Wire(w) => JsError::new(&format!("Wire: {w:?}")),
        EncryptError::Crypto(c) => JsError::new(&format!("Crypto: {c:?}")),
        EncryptError::Ephemeral(e) => JsError::new(&format!("Ephemeral: {e:?}")),
        EncryptError::DiversifierSearchExhausted => {
            JsError::new("DiversifierSearchExhausted")
        }
    }
}

fn build_result_object(result: &EncryptResult) -> Result<JsValue, JsValue> {
    let cmm_entry = Object::new();
    Reflect::set(
        &cmm_entry,
        &JsValue::from_str("vdxfKey"),
        &Uint8Array::from(&result.cmm_entry.0[..]).into(),
    )?;
    Reflect::set(
        &cmm_entry,
        &JsValue::from_str("value"),
        &Uint8Array::from(&result.cmm_entry.1[..]).into(),
    )?;

    let ret = Object::new();
    Reflect::set(&ret, &JsValue::from_str("cmmEntry"), &cmm_entry.into())?;

    let scripts_array = Array::new();
    for script in &result.data_deposit_output_scripts {
        scripts_array.push(&Uint8Array::from(&script[..]).into());
    }
    Reflect::set(
        &ret,
        &JsValue::from_str("dataDepositOutputScripts"),
        &scripts_array.into(),
    )?;
    Reflect::set(
        &ret,
        &JsValue::from_str("publishedIvk"),
        &Uint8Array::from(&result.published_ivk[..]).into(),
    )?;
    Reflect::set(
        &ret,
        &JsValue::from_str("outerEpk"),
        &Uint8Array::from(&result.outer_epk[..]).into(),
    )?;
    Reflect::set(
        &ret,
        &JsValue::from_str("ephemeralDiversifier"),
        &Uint8Array::from(&result.ephemeral_diversifier[..]).into(),
    )?;
    Reflect::set(
        &ret,
        &JsValue::from_str("ephemeralPkD"),
        &Uint8Array::from(&result.ephemeral_pk_d[..]).into(),
    )?;

    Ok(ret.into())
}
