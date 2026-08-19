//! Reproduces the byte-parity experiment's stage-1 decrypt against a real
//! daemon-written flags:13 outer descriptor, using ONLY this crate's public
//! `crypto` module. Serves as the anchor regression: if any of the KDF, DH,
//! or AEAD primitives ever drifts from the daemon, this test breaks.
//!
//! Fixture: `tests/fixtures/t1_578528.json` (t1@ vrsctest, height 578528).
//! Same JSON used by `byte-parity-experiment` under
//! `chainvue-things/flags13-writer-lib/scoping/byte-parity-experiment/`.

use verusid_cmm_encrypt::crypto::{aead_decrypt, kdf_sapling, sapling_ka_agree};
use verusid_cmm_encrypt::vdxf::{write_cvdxf_data, DATA_DESCRIPTOR_KEY_LE};

/// `DataDescriptorKey` i-address (`i4GC1YGEVD21afWudGoFJVdnfjJ5XWnCQv`)
/// hash160 in canonical big-endian order.
const DATA_DESCRIPTOR_KEY_HEX_BE: &str = "4d4f12424ded2033a526a4e2a8835fc5b2eba208";

#[test]
fn stage1_decrypt_of_daemon_written_entry_matches_expected_framing() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).expect("parse fixture json");
    let outer = &fixture["outerDescriptor"];

    let ivk = hex_to_32(outer["ivk"].as_str().expect("ivk field"));
    let epk = hex_to_32(outer["epk"].as_str().expect("epk field"));
    let ciphertext = hex::decode(outer["objectdata"].as_str().expect("objectdata field"))
        .expect("valid hex objectdata");

    let dhsecret = sapling_ka_agree(&ivk, &epk).expect("DH shared secret");
    let key = kdf_sapling(&dhsecret, &epk);
    let plaintext = aead_decrypt(&key, &ciphertext).expect("AEAD tag verifies");

    // Structural framing check: plaintext is a CVDXF header whose 20-byte
    // key is the DataDescriptorKey i-address hash160 in wire-order LE.
    let ddk_le: Vec<u8> = hex::decode(DATA_DESCRIPTOR_KEY_HEX_BE)
        .expect("hex")
        .into_iter()
        .rev()
        .collect();
    assert!(
        plaintext.starts_with(&ddk_le),
        "stage-1 plaintext should start with DataDescriptorKey (LE hash160); got prefix {}",
        hex::encode(&plaintext[..20])
    );

    // Immediately after the 20-byte key: VARINT version = 1 (one byte: 0x01).
    assert_eq!(
        plaintext[20], 0x01,
        "byte after CVDXF key should be VARINT version=1"
    );

    // Then CompactSize length prefix for the wrapped CDataDescriptor bytes.
    // For this small fixture the prefix is a single byte < 0xFD.
    assert!(
        plaintext[21] < 0xFD,
        "wrapped-descriptor length prefix should fit in the 1-byte CompactSize form for this fixture"
    );
    let inner_len = usize::from(plaintext[21]);
    assert_eq!(
        22 + inner_len,
        plaintext.len(),
        "CompactSize declared length ({inner_len}B) should account for the rest of the plaintext"
    );
}

/// Round-trip check: the stage-1 plaintext IS a serialized `CVDXF_Data`, so
/// if we peel off its 22-byte header + `inner` bytes and hand `inner` back
/// to `write_cvdxf_data` we must reproduce the plaintext byte-for-byte.
/// This is the framing side's counterpart to the crypto side's decrypt.
#[test]
fn cvdxf_data_reserializes_the_stage1_plaintext_byte_for_byte() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).expect("parse fixture json");
    let outer = &fixture["outerDescriptor"];

    let ivk = hex_to_32(outer["ivk"].as_str().unwrap());
    let epk = hex_to_32(outer["epk"].as_str().unwrap());
    let ciphertext = hex::decode(outer["objectdata"].as_str().unwrap()).unwrap();
    let dhsecret = sapling_ka_agree(&ivk, &epk).unwrap();
    let key = kdf_sapling(&dhsecret, &epk);
    let plaintext = aead_decrypt(&key, &ciphertext).unwrap();

    // The plaintext layout is: 20B key + VARINT(version=1) + CompactSize(len) + len bytes.
    // For this fixture the length prefix is a single byte < 0xFD.
    assert_eq!(&plaintext[..20], &DATA_DESCRIPTOR_KEY_LE);
    assert_eq!(plaintext[20], 0x01);
    assert!(plaintext[21] < 0xFD);
    let inner = &plaintext[22..];

    let mut reserialized = Vec::new();
    write_cvdxf_data(&mut reserialized, &DATA_DESCRIPTOR_KEY_LE, 1, inner);
    assert_eq!(reserialized, plaintext);
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("valid 32B hex");
    out
}
