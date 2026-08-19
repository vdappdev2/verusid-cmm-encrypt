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
