//! Reproduces the byte-parity experiment's stage-1 decrypt against a real
//! daemon-written flags:13 outer descriptor, using ONLY this crate's public
//! `crypto` module. Serves as the anchor regression: if any of the KDF, DH,
//! or AEAD primitives ever drifts from the daemon, this test breaks.
//!
//! Fixture: `tests/fixtures/t1_578528.json` (t1@ vrsctest, height 578528).
//! Same JSON used by `byte-parity-experiment` under
//! `chainvue-things/flags13-writer-lib/scoping/byte-parity-experiment/`.

use verusid_cmm_encrypt::crypto::{aead_decrypt, kdf_sapling, sapling_ka_agree};
use verusid_cmm_encrypt::data_descriptor::{
    wrap_encrypted_with_key, write_data_descriptor, DataDescriptor,
};
use verusid_cmm_encrypt::data_ref::{write_cvdxf_data_ref_self_ref, SelfRefPointer};
use verusid_cmm_encrypt::notary_evidence::{
    write_notary_evidence_for_envelope, EvidenceEntry,
};
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

/// The 66 inner bytes of the stage-1 plaintext (everything after the
/// `CVDXF_Data` header) are themselves a serialized `CDataDescriptor`.
/// Parse its version + flags + objectData framing, then hand the objectData
/// back to `write_data_descriptor` and assert we reproduce the full inner.
#[test]
fn data_descriptor_reserializes_the_stage1_inner_byte_for_byte() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let outer = &fixture["outerDescriptor"];

    let ivk = hex_to_32(outer["ivk"].as_str().unwrap());
    let epk = hex_to_32(outer["epk"].as_str().unwrap());
    let ciphertext = hex::decode(outer["objectdata"].as_str().unwrap()).unwrap();
    let dhsecret = sapling_ka_agree(&ivk, &epk).unwrap();
    let key = kdf_sapling(&dhsecret, &epk);
    let plaintext = aead_decrypt(&key, &ciphertext).unwrap();

    // Peel off the 22-byte CVDXF_Data header (20B key + VARINT + CompactSize).
    let inner_ddesc = &plaintext[22..];

    // Parse the inner as a bare CDataDescriptor. For this fixture it is
    // version=1, flags=0 (plaintext), object_data = the trailing bytes.
    assert_eq!(inner_ddesc[0], 0x01, "inner VARINT version = 1");
    assert_eq!(inner_ddesc[1], 0x00, "inner VARINT flags = 0 (plaintext CCDR pointer)");
    // Byte 2 is CompactSize length of objectData; must fit in single byte for this fixture.
    assert!(inner_ddesc[2] < 0xFD);
    let object_data_len = usize::from(inner_ddesc[2]);
    assert_eq!(
        3 + object_data_len,
        inner_ddesc.len(),
        "flags=0 inner has no trailing optional fields"
    );
    let object_data = &inner_ddesc[3..];

    let mut reserialized = Vec::new();
    write_data_descriptor(
        &mut reserialized,
        &DataDescriptor::new(object_data),
    )
    .unwrap();
    assert_eq!(reserialized, inner_ddesc);
}

/// End-to-end encrypt-side byte-parity milestone.
///
/// Given the daemon-written outer descriptor from the fixture, reconstruct
/// the inputs that produced it (the inner `CDataDescriptor` and the
/// symmetric key `K`) and re-encrypt through `wrap_encrypted_with_key`.
/// The output must equal the fixture's `objectdata` byte-for-byte.
///
/// This is the first encrypt-side check that exercises the full stack:
/// wire helpers + `CDataDescriptor` serialization + `CVDXF_Data` wrapping +
/// AEAD encryption. Any drift in any layer breaks the assertion.
///
/// We can compute `K` without knowing the daemon's `esk` because Sapling
/// KA agreement is symmetric: `esk * pk_d.mul_by_cofactor()` (encrypt)
/// equals `ivk * epk.mul_by_cofactor()` (decrypt), and `K` = KDF(that, epk)
/// either way.
#[test]
fn wrap_encrypted_reproduces_fixture_ciphertext_byte_for_byte() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let outer = &fixture["outerDescriptor"];

    let ivk = hex_to_32(outer["ivk"].as_str().unwrap());
    let epk = hex_to_32(outer["epk"].as_str().unwrap());
    let ciphertext = hex::decode(outer["objectdata"].as_str().unwrap()).unwrap();

    // Derive K via the decrypt-side agreement (already proven byte-parity).
    let dhsecret = sapling_ka_agree(&ivk, &epk).unwrap();
    let k = kdf_sapling(&dhsecret, &epk);

    // Decrypt to recover the CVDXF_Data-wrapped inner descriptor, then
    // extract the inner's raw fields so we can reconstruct it as a
    // `DataDescriptor` and re-encrypt.
    let plaintext = aead_decrypt(&k, &ciphertext).unwrap();
    let inner_bytes = &plaintext[22..];
    // The fixture's inner is version=1, flags=0, small objectData.
    assert_eq!(inner_bytes[0], 0x01);
    assert_eq!(inner_bytes[1], 0x00);
    assert!(inner_bytes[2] < 0xFD);
    let object_data_len = usize::from(inner_bytes[2]);
    let object_data = &inner_bytes[3..3 + object_data_len];

    let inner_dd = DataDescriptor {
        object_data,
        version: 1,
        ..Default::default()
    };

    let wrapped = wrap_encrypted_with_key(&inner_dd, &k, &epk).unwrap();
    assert_eq!(
        wrapped.object_data, ciphertext,
        "encrypt-side output must match daemon's ciphertext byte-for-byte"
    );
    assert_eq!(wrapped.epk, epk);
}

/// Anchor for the `CVDXFDataRef` self-ref primitive. Extract the 63-byte
/// `objectData` from the fixture's inner `CDataDescriptor` (which is a
/// serialized `CVDXFDataRef` pointing at the tx's data-deposit output) and
/// assert `write_cvdxf_data_ref_self_ref` reproduces it byte-for-byte.
///
/// For the t1_578528 fixture the data-deposit output sits at vout 0, so
/// the pointer is (vout=0, obj=0, sub=0). If any of the nested
/// CVDXFDataRef / CCrossChainDataRef / CPBaaSEvidenceRef serialization
/// drifts, this test breaks.
#[test]
fn cvdxf_data_ref_self_ref_reproduces_fixture_inner_object_data() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let outer = &fixture["outerDescriptor"];

    let ivk = hex_to_32(outer["ivk"].as_str().unwrap());
    let epk = hex_to_32(outer["epk"].as_str().unwrap());
    let ciphertext = hex::decode(outer["objectdata"].as_str().unwrap()).unwrap();
    let dhsecret = sapling_ka_agree(&ivk, &epk).unwrap();
    let key = kdf_sapling(&dhsecret, &epk);
    let plaintext = aead_decrypt(&key, &ciphertext).unwrap();

    // Layers: 22B CVDXF_Data header | inner CDataDescriptor (VARINT v=1,
    // VARINT flags=0, CompactSize len=63, 63B objectData).
    let inner_ddesc = &plaintext[22..];
    assert_eq!(inner_ddesc[0], 0x01);
    assert_eq!(inner_ddesc[1], 0x00);
    assert_eq!(inner_ddesc[2], 0x3F, "inner objectData is 63 bytes");
    let object_data = &inner_ddesc[3..3 + 63];

    let mut rebuilt = Vec::new();
    write_cvdxf_data_ref_self_ref(
        &mut rebuilt,
        &SelfRefPointer {
            vout_index: 0,
            object_num: 0,
            sub_object: 0,
        },
    );
    assert_eq!(rebuilt, object_data);
}

/// End-to-end byte-parity for CNotaryEvidence framing.
///
/// The fixture's `rawTx` contains an `EVAL_NOTARY_EVIDENCE` data-deposit
/// output whose scriptPubKey wraps a serialized `CNotaryEvidence`. We
/// locate that serialization inside the raw tx (by searching for its
/// fixed prefix), extract the systemID + inner CEvidenceData dataVec,
/// then reconstruct the CNotaryEvidence with our writer and assert
/// byte-exact equality against the real bytes.
///
/// This proves the entire framing stack — CNotaryEvidence, CCrossChainProof,
/// CChainObject header, and CEvidenceData (including the double-VARINT-version
/// quirk) — matches the daemon byte-for-byte. What is *not* proven at this
/// layer is the surrounding CryptoCondition script wrapping; that lands
/// with the EVAL_NOTARY_EVIDENCE CC-script slice.
#[test]
fn notary_evidence_reproduces_fixture_data_deposit_payload_byte_for_byte() {
    let raw = include_str!("fixtures/t1_578528.json");
    let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
    let raw_tx = hex::decode(fixture["rawTx"].as_str().unwrap()).unwrap();

    // Locate the CNotaryEvidence prefix: 0x01 (version) | 0x03 (TYPE_IMPORT_PROOF)
    // | 20B systemID | 32B zero hash | 4B zero n | 0x02 (STATE_SUPPORTING).
    // 36 consecutive zeros followed by 0x02 is a strong anchor.
    let start = find_notary_evidence_start(&raw_tx).expect("notary evidence prefix");

    let system_id: [u8; 20] = raw_tx[start + 2..start + 22].try_into().unwrap();

    // The CCrossChainProof begins at start+59. version (4B LE=1) then
    // VARINT(count). For this fixture count = 1 (payload only, no signature).
    assert_eq!(&raw_tx[start + 59..start + 63], &[0x01, 0x00, 0x00, 0x00]);
    assert_eq!(raw_tx[start + 63], 0x01, "one chain object");

    // Chain object header (2B) at start+64; CEvidenceData at start+66.
    assert_eq!(&raw_tx[start + 64..start + 66], &[0x0A, 0x00]);
    let ced_offset = start + 66;
    assert_eq!(raw_tx[ced_offset], 0x01, "CEvidenceData VARINT version #1");
    assert_eq!(raw_tx[ced_offset + 1], 0x01, "CEvidenceData VARINT version #2 (daemon quirk)");
    assert_eq!(raw_tx[ced_offset + 2], 0x01, "CEvidenceData VARINT type=TYPE_DATA");
    let vdxf_offset = ced_offset + 3;
    let vdxf_key: [u8; 20] = raw_tx[vdxf_offset..vdxf_offset + 20].try_into().unwrap();
    assert_eq!(vdxf_key, DATA_DESCRIPTOR_KEY_LE);

    // dataVec CompactSize + data. This fixture has dataVec > 252 bytes so the
    // CompactSize is 3 bytes (0xFD + u16 LE).
    let cs_offset = vdxf_offset + 20;
    assert_eq!(raw_tx[cs_offset], 0xFD, "expect 3-byte CompactSize form");
    let data_len = u16::from_le_bytes([raw_tx[cs_offset + 1], raw_tx[cs_offset + 2]]) as usize;
    let data_start = cs_offset + 3;
    let data_end = data_start + data_len;
    let data_vec = &raw_tx[data_start..data_end];

    // The whole CNotaryEvidence extent — everything from `start` up to and
    // including the final dataVec byte.
    let expected = &raw_tx[start..data_end];

    let mut rebuilt = Vec::new();
    write_notary_evidence_for_envelope(
        &mut rebuilt,
        &system_id,
        &[EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: data_vec,
        }],
    );
    assert_eq!(rebuilt, expected);
}

fn find_notary_evidence_start(bytes: &[u8]) -> Option<usize> {
    // Fixed pattern: 01 03 <20 bytes> <36 zero bytes> 02
    // Total prefix length being validated: 59 bytes.
    if bytes.len() < 59 {
        return None;
    }
    for i in 0..bytes.len() - 59 {
        if bytes[i] != 0x01 || bytes[i + 1] != 0x03 {
            continue;
        }
        if bytes[i + 22..i + 58].iter().any(|&b| b != 0) {
            continue;
        }
        if bytes[i + 58] != 0x02 {
            continue;
        }
        // Extra sanity: CCrossChainProof version at i+59 should be 1 (u32 LE).
        if i + 63 >= bytes.len() || &bytes[i + 59..i + 63] != [0x01, 0x00, 0x00, 0x00] {
            continue;
        }
        return Some(i);
    }
    None
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("valid 32B hex");
    out
}
