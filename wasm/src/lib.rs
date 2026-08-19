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
//! const result = encryptPublicDecrypt(
//!   plaintextU8,       // Uint8Array
//!   outerVdxfKeyU8,    // Uint8Array, exactly 20 bytes (LE from getvdxfid)
//!   systemIdU8,        // Uint8Array, exactly 20 bytes (LE ASSETCHAINS_CHAINID)
//!   label,             // string | null | undefined
//!   mimeType,          // string | null | undefined
//!   dataDepositVoutIndex, // number, u32
//! );
//! // result: {
//! //   cmmEntry: { vdxfKey: Uint8Array, value: Uint8Array },
//! //   dataDepositOutputScript: Uint8Array,
//! //   publishedIvk: Uint8Array,
//! //   outerEpk: Uint8Array,
//! //   ephemeralDiversifier: Uint8Array,
//! //   ephemeralPkD: Uint8Array,
//! // }
//! ```

use js_sys::{Object, Reflect, Uint8Array};
use rand_core::OsRng;
use verusid_cmm_encrypt::{
    encrypt_public_decrypt, EncryptError, EncryptRequest, EncryptResult,
};
use wasm_bindgen::prelude::*;

/// Encrypt `plaintext` into a `flags:13` public-decrypt cmm entry and its
/// accompanying `EVAL_NOTARY_EVIDENCE` data-deposit output.
///
/// See the module-level docs for the JS input/output shape. Errors surface as
/// JavaScript `Error` instances with a message identifying the failing layer
/// (`Wire`, `Crypto`, `Ephemeral`, `DiversifierSearchExhausted`, or an input
/// validation message).
#[wasm_bindgen(js_name = encryptPublicDecrypt)]
pub fn encrypt_public_decrypt_js(
    plaintext: Uint8Array,
    outer_vdxf_key: Uint8Array,
    system_id: Uint8Array,
    label: Option<String>,
    mime_type: Option<String>,
    data_deposit_vout_index: u32,
) -> Result<JsValue, JsError> {
    let outer_vdxf_key = to_20b(&outer_vdxf_key, "outerVdxfKey")?;
    let system_id = to_20b(&system_id, "systemId")?;
    let plaintext_bytes = plaintext.to_vec();

    let request = EncryptRequest {
        plaintext: &plaintext_bytes,
        outer_vdxf_key,
        system_id,
        label: label.as_deref(),
        mime_type: mime_type.as_deref(),
        data_deposit_vout_index,
    };

    let mut rng = OsRng;
    let result =
        encrypt_public_decrypt(&request, &mut rng).map_err(map_encrypt_error)?;

    build_result_object(&result)
        .map_err(|_| JsError::new("failed to construct result object"))
}

fn to_20b(arr: &Uint8Array, name: &str) -> Result<[u8; 20], JsError> {
    let len = arr.length() as usize;
    if len != 20 {
        return Err(JsError::new(&format!(
            "{name} must be exactly 20 bytes, got {len}"
        )));
    }
    let mut out = [0u8; 20];
    arr.copy_to(&mut out);
    Ok(out)
}

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
    Reflect::set(
        &ret,
        &JsValue::from_str("dataDepositOutputScript"),
        &Uint8Array::from(&result.data_deposit_output_script[..]).into(),
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
