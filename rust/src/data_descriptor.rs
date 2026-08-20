//! `CDataDescriptor` — the flags-gated inner struct that carries the
//! encrypted payload (or its plaintext form) inside every envelope entry.
//!
//! Ported from `VerusCoin/src/pbaas/vdxf.h:944-1147` at commit
//! `d1df9b7d254aacbc12070da48640edf84312200b`.
//!
//! Serialization order (SerializationOp at `vdxf.h:1005-1042`):
//!
//! 1. `VARINT(version)` — always
//! 2. `VARINT(flags)` — always; recomputed by `SetFlags` at write time
//! 3. `vdxfKey` (20B LE) — iff `FLAG_VDXF_KEY_PRESENT`
//! 4. `objectData` (var bytes) — always
//! 5. `LIMITED_STRING(label, 64)` — iff `FLAG_LABEL_PRESENT`
//! 6. `LIMITED_STRING(mimeType, 128)` — iff `FLAG_MIME_TYPE_PRESENT`
//! 7. `salt` (var bytes) — iff `FLAG_SALT_PRESENT`
//! 8. `epk` (var bytes) — iff `FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT`
//! 9. `ivk` (var bytes) — iff `FLAG_INCOMING_VIEWING_KEY_PRESENT`
//! 10. `ssk` (var bytes) — iff `FLAG_SYMMETRIC_ENCRYPTION_KEY_PRESENT`
//!
//! Presence bits are derived by `CalcFlags` from which optional fields have
//! non-empty content. The one exception is `FLAG_ENCRYPTED_DATA`, which is
//! preserved from the caller — it declares whether `objectData` is
//! ciphertext (with a Poly1305 tag) or opaque plaintext bytes. `CalcFlags`
//! at `vdxf.h:1101-1111` reads: `(flags & FLAG_ENCRYPTED_DATA) + ...`.

use crate::crypto::aead_encrypt;
use crate::vdxf::{write_cvdxf_data, DATA_DESCRIPTOR_KEY_LE};
use crate::wire::{write_limited_string, write_var_bytes, write_varint_u64, WireError};

/// Default and only supported `CDataDescriptor` version. `vdxf.h:951`.
pub const DEFAULT_VERSION: u32 = 1;

/// The payload in `object_data` is AEAD ciphertext (plaintext bytes + 16B
/// Poly1305 tag), not raw bytes. Preserved from the caller by `calc_flags`.
pub const FLAG_ENCRYPTED_DATA: u32 = 0x01;
/// `salt` is present.
pub const FLAG_SALT_PRESENT: u32 = 0x02;
/// `epk` is present — the Sapling ephemeral public key that decrypts
/// `object_data`.
pub const FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT: u32 = 0x04;
/// `ivk` is present — the Sapling incoming viewing key. In flags:13
/// public-decrypt entries this is what makes the payload publicly readable.
pub const FLAG_INCOMING_VIEWING_KEY_PRESENT: u32 = 0x08;
/// `ssk` is present — a specific symmetric key that decrypts only this
/// entry.
pub const FLAG_SYMMETRIC_ENCRYPTION_KEY_PRESENT: u32 = 0x10;
/// `label` is present and non-empty.
pub const FLAG_LABEL_PRESENT: u32 = 0x20;
/// `mime_type` is present and non-empty.
pub const FLAG_MIME_TYPE_PRESENT: u32 = 0x40;
/// `vdxf_key` is present and non-null.
pub const FLAG_VDXF_KEY_PRESENT: u32 = 0x80;

/// Inputs to build one `CDataDescriptor`. Empty `Option::Some` values
/// (`Some("")`, `Some(&[])`) are treated as absent, matching the daemon's
/// `.size() ? PRESENT : 0` convention in `CalcFlags`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DataDescriptor<'a> {
    /// `true` sets `FLAG_ENCRYPTED_DATA`, declaring `object_data` is
    /// AEAD ciphertext.
    pub encrypted: bool,
    /// Optional per-entry discriminator (a narrower VDXF i-address). When
    /// present, sets `FLAG_VDXF_KEY_PRESENT`.
    pub vdxf_key: Option<&'a [u8; 20]>,
    /// The payload — ciphertext when `encrypted` is `true`, otherwise raw
    /// bytes or a serialized inner structure (e.g., a `CVDXFDataRef`).
    pub object_data: &'a [u8],
    /// Optional UTF-8 label. Capped at 64 bytes on serialize
    /// (`LIMITED_STRING(label, 64)`).
    pub label: Option<&'a str>,
    /// Optional MIME type. Capped at 128 bytes
    /// (`LIMITED_STRING(mimeType, 128)`).
    pub mime_type: Option<&'a str>,
    /// Optional salt bytes.
    pub salt: Option<&'a [u8]>,
    /// Optional Sapling ephemeral public key.
    pub epk: Option<&'a [u8]>,
    /// Optional Sapling incoming viewing key.
    pub ivk: Option<&'a [u8]>,
    /// Optional specific symmetric key.
    pub ssk: Option<&'a [u8]>,
    /// Serialization version. Defaults to [`DEFAULT_VERSION`] (= 1).
    pub version: u32,
}

impl<'a> DataDescriptor<'a> {
    /// Convenience: descriptor with default version 1 and everything empty.
    pub fn new(object_data: &'a [u8]) -> Self {
        Self {
            object_data,
            version: DEFAULT_VERSION,
            ..Self::default()
        }
    }
}

/// Compute the flag bitmask that would be emitted for `dd`. Mirrors
/// `CDataDescriptor::CalcFlags` at `vdxf.h:1101-1111`.
pub fn calc_flags(dd: &DataDescriptor<'_>) -> u32 {
    let mut f = 0u32;
    if dd.encrypted {
        f |= FLAG_ENCRYPTED_DATA;
    }
    if dd.vdxf_key.is_some() {
        f |= FLAG_VDXF_KEY_PRESENT;
    }
    if is_nonempty_str(dd.label) {
        f |= FLAG_LABEL_PRESENT;
    }
    if is_nonempty_str(dd.mime_type) {
        f |= FLAG_MIME_TYPE_PRESENT;
    }
    if is_nonempty_bytes(dd.salt) {
        f |= FLAG_SALT_PRESENT;
    }
    if is_nonempty_bytes(dd.epk) {
        f |= FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT;
    }
    if is_nonempty_bytes(dd.ivk) {
        f |= FLAG_INCOMING_VIEWING_KEY_PRESENT;
    }
    if is_nonempty_bytes(dd.ssk) {
        f |= FLAG_SYMMETRIC_ENCRYPTION_KEY_PRESENT;
    }
    f
}

/// Serialize `dd` in the daemon's flags-gated field order. Returns
/// `WireError::LimitedStringTooLong` if `label` exceeds 64 bytes or
/// `mime_type` exceeds 128 bytes.
///
/// Version defaults to 1 when `dd.version == 0`, matching the constructor
/// default at `vdxf.h:976-978`.
pub fn write_data_descriptor(
    buf: &mut Vec<u8>,
    dd: &DataDescriptor<'_>,
) -> Result<(), WireError> {
    let version = if dd.version == 0 { DEFAULT_VERSION } else { dd.version };
    let flags = calc_flags(dd);

    write_varint_u64(buf, u64::from(version));
    write_varint_u64(buf, u64::from(flags));

    if flags & FLAG_VDXF_KEY_PRESENT != 0 {
        buf.extend_from_slice(dd.vdxf_key.expect("guarded by flag bit"));
    }
    write_var_bytes(buf, dd.object_data);
    if flags & FLAG_LABEL_PRESENT != 0 {
        write_limited_string(buf, dd.label.expect("guarded by flag bit"), 64)?;
    }
    if flags & FLAG_MIME_TYPE_PRESENT != 0 {
        write_limited_string(buf, dd.mime_type.expect("guarded by flag bit"), 128)?;
    }
    if flags & FLAG_SALT_PRESENT != 0 {
        write_var_bytes(buf, dd.salt.expect("guarded by flag bit"));
    }
    if flags & FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT != 0 {
        write_var_bytes(buf, dd.epk.expect("guarded by flag bit"));
    }
    if flags & FLAG_INCOMING_VIEWING_KEY_PRESENT != 0 {
        write_var_bytes(buf, dd.ivk.expect("guarded by flag bit"));
    }
    if flags & FLAG_SYMMETRIC_ENCRYPTION_KEY_PRESENT != 0 {
        write_var_bytes(buf, dd.ssk.expect("guarded by flag bit"));
    }
    Ok(())
}

/// Output of [`wrap_encrypted_with_key`] — the two byte fields the caller
/// needs to populate on the outer `DataDescriptor`.
#[derive(Debug, Clone)]
pub struct WrappedEncrypted {
    /// AEAD ciphertext (plaintext + 16-byte Poly1305 tag). Becomes
    /// `outer.object_data`.
    pub object_data: Vec<u8>,
    /// The Sapling ephemeral public key that decrypts `object_data` (when
    /// combined with a valid `ivk`). Becomes `outer.epk`.
    pub epk: [u8; 32],
}

/// Compose the daemon's `CDataDescriptor::WrapEncrypted`
/// (`vdxf.h:1050-1064`): serialize `inner`, wrap in a
/// `CVDXF_Data(DataDescriptorKey, ...)` envelope, and AEAD-encrypt the whole
/// thing with `symmetric_key`.
///
/// This is the low-level primitive. The caller supplies the derived
/// symmetric key `K` (= `KDF_Sapling(dhsecret, epk)`) and the matching
/// ephemeral public key `epk`. The daemon derives both from a fresh random
/// `esk` and the recipient `SaplingPaymentAddress`
/// (`vdxf.cpp:614-656`); the higher-level API that does that end-to-end
/// derivation is deferred until the ephemeral-key module lands.
///
/// The caller then constructs the outer `DataDescriptor` themselves,
/// filling `encrypted: true`, `object_data`, and `epk` from the returned
/// value and optionally adding `ivk` (turning `flags:5` into `flags:13`).
pub fn wrap_encrypted_with_key(
    inner: &DataDescriptor<'_>,
    symmetric_key: &[u8; 32],
    epk: &[u8; 32],
) -> Result<WrappedEncrypted, WireError> {
    // 1. Serialize the inner CDataDescriptor.
    let mut inner_bytes = Vec::new();
    write_data_descriptor(&mut inner_bytes, inner)?;

    // 2. Wrap it in CVDXF_Data(DataDescriptorKey, inner_bytes). This is the
    //    plaintext handed to AEAD encrypt. It matches nestedObject at
    //    vdxf.h:1053.
    let mut plaintext = Vec::new();
    write_cvdxf_data(&mut plaintext, &DATA_DESCRIPTOR_KEY_LE, 1, &inner_bytes);

    // 3. AEAD-encrypt. Zero nonce is safe because K is derived from a fresh
    //    esk per call; see the daemon comment at vdxf.cpp:564.
    let ciphertext = aead_encrypt(symmetric_key, &plaintext);

    Ok(WrappedEncrypted {
        object_data: ciphertext,
        epk: *epk,
    })
}

fn is_nonempty_str(s: Option<&str>) -> bool {
    s.map_or(false, |v| !v.is_empty())
}

fn is_nonempty_bytes(b: Option<&[u8]>) -> bool {
    b.map_or(false, |v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_flags_plaintext_only_object_data_is_zero() {
        let dd = DataDescriptor::new(&[0x42]);
        assert_eq!(calc_flags(&dd), 0);
    }

    #[test]
    fn calc_flags_encrypted_flag_is_preserved_regardless_of_other_fields() {
        // FLAG_ENCRYPTED_DATA is the caller's declaration, not derived
        // from field presence — the daemon's CalcFlags reads
        // `(flags & FLAG_ENCRYPTED_DATA) + ...` so we must carry it through.
        let mut dd = DataDescriptor::new(&[0x00]);
        dd.encrypted = true;
        assert_eq!(calc_flags(&dd), FLAG_ENCRYPTED_DATA);
    }

    #[test]
    fn calc_flags_matches_daemon_flags5_shape() {
        // flags:5 = FLAG_ENCRYPTED_DATA (1) | FLAG_ENCRYPTION_PUBLIC_KEY_PRESENT (4)
        // This is the shape signdata emits before the daemon layers IVK on top.
        let epk = [0x11u8; 32];
        let dd = DataDescriptor {
            encrypted: true,
            object_data: &[0xAA; 8],
            epk: Some(&epk),
            version: 1,
            ..Default::default()
        };
        assert_eq!(calc_flags(&dd), 5);
    }

    #[test]
    fn calc_flags_matches_daemon_flags13_shape() {
        // flags:13 = 5 | FLAG_INCOMING_VIEWING_KEY_PRESENT (8) = 13.
        // This is the outer descriptor shape the envelope path emits into cmm.
        let epk = [0x11u8; 32];
        let ivk = [0x22u8; 32];
        let dd = DataDescriptor {
            encrypted: true,
            object_data: &[0xAA; 8],
            epk: Some(&epk),
            ivk: Some(&ivk),
            version: 1,
            ..Default::default()
        };
        assert_eq!(calc_flags(&dd), 13);
    }

    #[test]
    fn calc_flags_treats_some_empty_as_absent_matching_daemon() {
        let dd = DataDescriptor {
            object_data: &[0x01],
            label: Some(""),      // empty string counts as absent
            mime_type: Some(""),
            salt: Some(&[]),      // empty vec counts as absent
            epk: Some(&[]),
            ivk: Some(&[]),
            ssk: Some(&[]),
            ..Default::default()
        };
        assert_eq!(calc_flags(&dd), 0);
    }

    #[test]
    fn calc_flags_all_optional_fields_set_produces_full_mask() {
        let key = [0u8; 20];
        let dd = DataDescriptor {
            encrypted: true,
            vdxf_key: Some(&key),
            object_data: &[0x01],
            label: Some("a"),
            mime_type: Some("b"),
            salt: Some(&[0x02]),
            epk: Some(&[0x03]),
            ivk: Some(&[0x04]),
            ssk: Some(&[0x05]),
            version: 1,
        };
        assert_eq!(calc_flags(&dd), 0xFF);
    }

    #[test]
    fn write_plain_descriptor_is_version_flags_and_objectdata() {
        let dd = DataDescriptor::new(&[0xAA, 0xBB, 0xCC]);
        let mut buf = Vec::new();
        write_data_descriptor(&mut buf, &dd).unwrap();
        // VARINT(1) | VARINT(0) | CompactSize(3) | 3 bytes
        assert_eq!(buf, vec![0x01, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn write_flags5_descriptor_has_epk_after_object_data() {
        let epk = [0x11u8; 32];
        let dd = DataDescriptor {
            encrypted: true,
            object_data: &[0xDE, 0xAD],
            epk: Some(&epk),
            version: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_data_descriptor(&mut buf, &dd).unwrap();
        // Expected: VARINT(1) VARINT(5) CompactSize(2) 0xDE 0xAD CompactSize(32) <32B epk>
        let mut expected = vec![0x01, 0x05, 0x02, 0xDE, 0xAD, 0x20];
        expected.extend_from_slice(&epk);
        assert_eq!(buf, expected);
    }

    #[test]
    fn write_flags13_descriptor_has_ivk_after_epk() {
        let epk = [0x11u8; 32];
        let ivk = [0x22u8; 32];
        let dd = DataDescriptor {
            encrypted: true,
            object_data: &[0xDE, 0xAD],
            epk: Some(&epk),
            ivk: Some(&ivk),
            version: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_data_descriptor(&mut buf, &dd).unwrap();
        let mut expected = vec![0x01, 0x0D, 0x02, 0xDE, 0xAD, 0x20];
        expected.extend_from_slice(&epk);
        expected.push(0x20);
        expected.extend_from_slice(&ivk);
        assert_eq!(buf, expected);
    }

    #[test]
    fn write_places_label_before_mime_and_before_optional_key_bytes() {
        // Full field order stress test.
        let key = [0xEEu8; 20];
        let dd = DataDescriptor {
            encrypted: true,
            vdxf_key: Some(&key),
            object_data: &[0xAA],
            label: Some("hi"),
            mime_type: Some("text/plain"),
            salt: Some(&[0x01, 0x02]),
            epk: Some(&[0x03; 32]),
            ivk: Some(&[0x04; 32]),
            ssk: Some(&[0x05; 32]),
            version: 1,
        };
        let mut buf = Vec::new();
        write_data_descriptor(&mut buf, &dd).unwrap();

        // Manually assemble expected bytes in field order.
        let mut expected = Vec::new();
        expected.push(0x01); // VARINT version
        expected.extend_from_slice(&[0x80, 0x7F]); // VARINT(0xFF) = full flags mask
        expected.extend_from_slice(&key); // vdxfKey (20B)
        expected.extend_from_slice(&[0x01, 0xAA]); // objectData (len=1, 0xAA)
        expected.extend_from_slice(&[0x02, b'h', b'i']); // label
        expected.push(0x0A); // mimeType len=10
        expected.extend_from_slice(b"text/plain");
        expected.extend_from_slice(&[0x02, 0x01, 0x02]); // salt
        expected.push(0x20);
        expected.extend_from_slice(&[0x03; 32]); // epk
        expected.push(0x20);
        expected.extend_from_slice(&[0x04; 32]); // ivk
        expected.push(0x20);
        expected.extend_from_slice(&[0x05; 32]); // ssk

        assert_eq!(buf, expected);
    }

    #[test]
    fn write_rejects_label_over_64_bytes() {
        let long = "L".repeat(65);
        let dd = DataDescriptor {
            object_data: &[0x00],
            label: Some(&long),
            version: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let err = write_data_descriptor(&mut buf, &dd).unwrap_err();
        assert_eq!(
            err,
            WireError::LimitedStringTooLong { cap: 64, actual: 65 }
        );
    }

    #[test]
    fn write_rejects_mime_type_over_128_bytes() {
        let long = "M".repeat(129);
        let dd = DataDescriptor {
            object_data: &[0x00],
            mime_type: Some(&long),
            version: 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let err = write_data_descriptor(&mut buf, &dd).unwrap_err();
        assert_eq!(
            err,
            WireError::LimitedStringTooLong { cap: 128, actual: 129 }
        );
    }

    #[test]
    fn wrap_encrypted_with_key_produces_deterministic_ciphertext_for_pinned_inputs() {
        // Fixed K + epk + inner descriptor → deterministic ciphertext, since
        // AEAD uses a zero nonce and encryption is a pure function of (K, plaintext).
        let inner = DataDescriptor::new(&[0x11, 0x22, 0x33]);
        let k = [0x55u8; 32];
        let epk = [0x77u8; 32];

        let a = wrap_encrypted_with_key(&inner, &k, &epk).unwrap();
        let b = wrap_encrypted_with_key(&inner, &k, &epk).unwrap();
        assert_eq!(a.object_data, b.object_data);
        assert_eq!(a.epk, epk);
    }

    #[test]
    fn wrap_encrypted_output_decrypts_back_to_the_cvdxf_wrapped_inner_bytes() {
        use crate::crypto::aead_decrypt;

        let inner = DataDescriptor::new(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let k = [0x99u8; 32];
        let epk = [0x88u8; 32];

        let wrapped = wrap_encrypted_with_key(&inner, &k, &epk).unwrap();
        let plaintext = aead_decrypt(&k, &wrapped.object_data).unwrap();

        // The plaintext is: CVDXF_Data header (20B key + 1B VARINT version=1
        // + 1B CompactSize length = 22B) followed by the serialized inner.
        // Inner serialization is: VARINT(1) VARINT(0) CompactSize(4) + 4B
        // objectData = 7 bytes.
        assert_eq!(&plaintext[..20], &DATA_DESCRIPTOR_KEY_LE);
        assert_eq!(plaintext[20], 0x01);
        assert_eq!(plaintext[21], 0x07, "inner descriptor is 7 bytes");
        assert_eq!(&plaintext[22..], &[0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn wrap_encrypted_output_length_is_inner_serialized_plus_22_plus_16() {
        // Overhead accounting: 20B CVDXF key + 1B VARINT version + 1B
        // CompactSize length (small payloads) + inner descriptor bytes +
        // 16B Poly1305 tag.
        let inner = DataDescriptor::new(&[0x00; 40]);
        let k = [0x01u8; 32];
        let epk = [0x02u8; 32];

        let wrapped = wrap_encrypted_with_key(&inner, &k, &epk).unwrap();
        // Inner serialized: VARINT(1) VARINT(0) CompactSize(40) + 40B = 43B
        // Plaintext: 22B header + 43B inner = 65B
        // Ciphertext: 65B + 16B tag = 81B
        assert_eq!(wrapped.object_data.len(), 81);
    }

    #[test]
    fn write_version_zero_falls_back_to_default() {
        let dd = DataDescriptor {
            object_data: &[0x00],
            version: 0,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_data_descriptor(&mut buf, &dd).unwrap();
        assert_eq!(buf[0], 0x01, "VARINT should have emitted the default version");
    }
}
