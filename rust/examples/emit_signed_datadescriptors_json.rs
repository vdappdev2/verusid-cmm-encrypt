//! Signature-attached counterpart to `emit_datadescriptor_json`. Emits TWO
//! `datadescriptor` JSON payloads — one for the data descriptor
//! (`sub_object=0`) and one for the signature descriptor (`sub_object=1`) —
//! so the daemon's `decryptdata` RPC can verify our signdata composition.
//!
//! Usage:
//! ```text
//! cargo run --example emit_signed_datadescriptors_json
//! # feed each block to a running daemon:
//! verus -chain=VRSCTEST decryptdata '<DATA block>'
//! verus -chain=VRSCTEST decryptdata '<SIGNATURE block>'
//! ```
//!
//! Expected: data block returns a CCDR with `voutnum` = the
//! `data_deposit_vout_index` and `subobject: 0`; signature block returns the
//! same `voutnum` with `subobject: 1`. Both `output.txid` are all zeros
//! (self-refs). The signature block's reply also includes the wrapped inner
//! CDD's label (`"signature"`) and mimetype (`"application/json"`).

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use verusid_cmm_encrypt::{encrypt_public_decrypt, EncryptRequest};

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE_u64);
    let sig = b"caller-supplied signature bytes (opaque to this crate)";
    let request = EncryptRequest {
        plaintext: b"data with signature attached",
        outer_vdxf_key: [0xAA; 20],
        system_id: [0xBB; 20],
        label: None,
        mime_type: None,
        data_deposit_vout_index: 4,
        signature: Some(sig),
    };
    let result = encrypt_public_decrypt(&request, &mut rng).expect("encrypt");

    // The cmm value carries two concatenated outer CDataDescriptors, each
    // laid out as: 0x01 (v) | 0x0D (flags) | CompactSize(N) | N ct | 0x20 | 32B epk | 0x20 | 32B ivk
    let bytes = &result.cmm_entry.1;
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x0D);
    assert!(bytes[2] < 0xFD);
    let ct_len_1 = usize::from(bytes[2]);
    let first_end = 3 + ct_len_1 + 33 + 33;

    // Data descriptor extraction (indices 0..first_end).
    let data_ct = &bytes[3..3 + ct_len_1];
    let data_epk: [u8; 32] = bytes[3 + ct_len_1 + 1..3 + ct_len_1 + 33]
        .try_into()
        .unwrap();
    let data_ivk: [u8; 32] = bytes[3 + ct_len_1 + 34..first_end]
        .try_into()
        .unwrap();

    // Signature descriptor (starts at first_end, same shape).
    let sig_bytes = &bytes[first_end..];
    assert_eq!(sig_bytes[0], 0x01);
    assert_eq!(sig_bytes[1], 0x0D);
    let ct_len_2 = usize::from(sig_bytes[2]);
    let sig_ct = &sig_bytes[3..3 + ct_len_2];
    let sig_epk: [u8; 32] = sig_bytes[3 + ct_len_2 + 1..3 + ct_len_2 + 33]
        .try_into()
        .unwrap();
    let sig_ivk: [u8; 32] = sig_bytes[3 + ct_len_2 + 34..3 + ct_len_2 + 33 + 33]
        .try_into()
        .unwrap();

    println!("=== DATA descriptor JSON ===");
    println!(
        r#"{{"datadescriptor":{{"version":1,"flags":13,"ivk":"{}","epk":"{}","objectdata":"{}"}}}}"#,
        hex::encode(data_ivk),
        hex::encode(data_epk),
        hex::encode(data_ct),
    );
    println!();
    println!("=== SIGNATURE descriptor JSON ===");
    println!(
        r#"{{"datadescriptor":{{"version":1,"flags":13,"ivk":"{}","epk":"{}","objectdata":"{}"}}}}"#,
        hex::encode(sig_ivk),
        hex::encode(sig_epk),
        hex::encode(sig_ct),
    );

    eprintln!();
    eprintln!("expected voutnum = {}", request.data_deposit_vout_index);
    eprintln!("expected DATA subobject = 0");
    eprintln!("expected SIGNATURE subobject = 1");
    eprintln!("expected SIGNATURE label = \"signature\", mimetype = \"application/json\"");
    eprintln!("both ivk values should match: {}", data_ivk == sig_ivk);
}
