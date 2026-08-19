//! Emit a single `datadescriptor` JSON payload suitable for feeding into a
//! running Verus daemon's `decryptdata` RPC. Purpose: Phase-2 verification
//! that our `encrypt_public_decrypt` output round-trips through librustzcash's
//! outer AEAD decrypt path exactly as the daemon expects.
//!
//! Usage:
//! ```text
//! cargo run --example emit_datadescriptor_json
//! # copy the printed JSON, then either:
//! verus -chain=VRSCTEST decryptdata '<paste JSON here>'
//! # or via any RPC client that hits the local daemon.
//! ```
//!
//! Expected daemon response: a single-element array containing a CCDR pointer
//! keyed under `CVDXF_Data::CrossChainDataRefKey()` with `output.voutnum` equal
//! to the `data_deposit_vout_index` printed on stderr, and `output.txid` all
//! zeros (envelope writes are self-refs; see the `daemon_envelope_ccdr_selfref`
//! memory).
//!
//! Deterministic: uses a seeded `ChaCha20Rng` so the printed JSON is
//! reproducible across runs and machines.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use verusid_cmm_encrypt::{encrypt_public_decrypt, EncryptRequest};

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE_u64);
    let request = EncryptRequest {
        plaintext: b"phase-2 verification payload",
        outer_vdxf_key: [0xAA; 20],
        system_id: [0xBB; 20],
        label: None,
        mime_type: None,
        data_deposit_vout_index: 7,
    };
    let result = encrypt_public_decrypt(&request, &mut rng).expect("encrypt");

    // Extract the outer AEAD ciphertext from the serialized CDataDescriptor.
    // Layout (flags:13 with no label/mime):
    //   0x01 (version=1) | 0x0D (flags=13) | CompactSize(N) | N-byte ciphertext
    //                    | 0x20 | 32B epk | 0x20 | 32B ivk
    // For plaintexts this small the ciphertext CompactSize is a single byte.
    let bytes = &result.cmm_entry.1;
    assert_eq!(bytes[0], 0x01, "version");
    assert_eq!(bytes[1], 0x0D, "flags:13");
    assert!(
        bytes[2] < 0xFD,
        "example expects single-byte CompactSize; enlarge parser for bigger payloads"
    );
    let ct_len = usize::from(bytes[2]);
    let ct = &bytes[3..3 + ct_len];

    // Emit the JSON in the exact shape decryptdata's CDataDescriptor(UniValue)
    // constructor accepts (see VerusCoin vdxf.cpp:696).
    println!(
        r#"{{"datadescriptor":{{"version":1,"flags":13,"ivk":"{}","epk":"{}","objectdata":"{}"}}}}"#,
        hex::encode(result.published_ivk),
        hex::encode(result.outer_epk),
        hex::encode(ct),
    );

    // Diagnostics on stderr so stdout stays clean for piping.
    eprintln!("expected voutnum = {}", request.data_deposit_vout_index);
    eprintln!("expected txid    = 00...00 (self-ref, envelope write)");
}
