//! Bitcoin-lineage serialization primitives used by VerusCoin's
//! `CDataStream` and consumed by every VDXF framing layer this crate emits.
//!
//! Byte-exact ports of:
//!
//! - `WriteCompactSize` / `ReadCompactSize` — `src/serialize.h:283-339`
//! - `WriteVarInt` / `ReadVarInt` — `src/serialize.h:378-417`
//! - `LIMITED_STRING(obj, n)` — `src/serialize.h:422`, using CompactSize
//!   length prefix with an `n`-byte cap enforced on write.
//!
//! CompactSize and VarInt are distinct encodings. CompactSize uses the
//! `<253 | 0xfd u16 | 0xfe u32 | 0xff u64>` little-endian pattern; VarInt is
//! the MSB base-128 encoding with the "subtract 1 from all but last digit"
//! canonicality trick.

use core::fmt;

/// Maximum readable size across the daemon's serialization layer
/// (`MAX_SIZE` at `src/serialize.h:30`). Reads that exceed this are rejected
/// as size-too-large.
pub const MAX_SIZE: u64 = 0x0200_0000;

/// Errors produced by the read-side helpers. Writer paths cannot fail beyond
/// the `LimitedStringTooLong` guard on `write_limited_string`.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// Reader hit end-of-buffer before completing a read.
    UnexpectedEof,
    /// A `CompactSize` was encoded with more bytes than the smallest legal
    /// form. Matches `"non-canonical ReadCompactSize()"` in the daemon.
    NonCanonicalCompactSize,
    /// A `CompactSize` decoded to a value larger than `MAX_SIZE`. Matches
    /// `"ReadCompactSize(): size too large"` in the daemon.
    CompactSizeTooLarge,
    /// A `VarInt` overflowed the target width during read. Matches
    /// `"ReadVarInt(): size too large"` in the daemon.
    VarIntTooLarge,
    /// A `LIMITED_STRING(obj, n)` write was attempted with a string longer
    /// than the declared cap `n`.
    LimitedStringTooLong {
        /// The declared maximum length (bytes) for the field.
        cap: usize,
        /// The actual UTF-8 byte length of the string that was submitted.
        actual: usize,
    },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of buffer"),
            WireError::NonCanonicalCompactSize => write!(f, "non-canonical CompactSize"),
            WireError::CompactSizeTooLarge => write!(f, "CompactSize exceeds MAX_SIZE"),
            WireError::VarIntTooLarge => write!(f, "VarInt too large for target width"),
            WireError::LimitedStringTooLong { cap, actual } => {
                write!(f, "LIMITED_STRING exceeded cap {cap} (was {actual})")
            }
        }
    }
}

impl std::error::Error for WireError {}

// --- CompactSize ------------------------------------------------------------

/// Append `n` as a Bitcoin-style `CompactSize` integer.
///
/// Encoding: `n < 253` → 1 byte; `n <= 0xFFFF` → `0xfd || u16 LE`;
/// `n <= 0xFFFFFFFF` → `0xfe || u32 LE`; else `0xff || u64 LE`.
pub fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u64::from(u32::MAX) {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Read a `CompactSize` at `cursor`, advance it past the encoded bytes,
/// and return the decoded value. Rejects non-canonical encodings and values
/// above `MAX_SIZE`, matching the daemon.
pub fn read_compact_size(buf: &[u8], cursor: &mut usize) -> Result<u64, WireError> {
    let tag = read_u8(buf, cursor)?;
    let n = match tag {
        n if n < 253 => u64::from(n),
        253 => {
            let v = read_u16_le(buf, cursor)?;
            if v < 253 {
                return Err(WireError::NonCanonicalCompactSize);
            }
            u64::from(v)
        }
        254 => {
            let v = read_u32_le(buf, cursor)?;
            if v < 0x1_0000 {
                return Err(WireError::NonCanonicalCompactSize);
            }
            u64::from(v)
        }
        _ => {
            let v = read_u64_le(buf, cursor)?;
            if v < 0x1_0000_0000 {
                return Err(WireError::NonCanonicalCompactSize);
            }
            v
        }
    };
    if n > MAX_SIZE {
        return Err(WireError::CompactSizeTooLarge);
    }
    Ok(n)
}

// --- VarInt (Bitcoin base-128 MSB) ------------------------------------------

/// Append `n` in the daemon's `VARINT` encoding.
///
/// Base-128 MSB with the canonicality trick: every byte except the last has
/// its high bit set; every byte except the last is decremented by one during
/// the loop. Encoding sizes: `0..=0x7F` → 1B, `0x80..=0x407F` → 2B,
/// `0x4080..=0x2040BF` → 3B, etc.
///
/// Direct port of `WriteVarInt` at `src/serialize.h:382-396`.
pub fn write_varint_u64(buf: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 10]; // (u64 bits + 6) / 7 = 10
    let mut len: usize = 0;
    loop {
        let marker: u8 = if len != 0 { 0x80 } else { 0x00 };
        tmp[len] = ((n & 0x7F) as u8) | marker;
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    // Emit high-order digit first (daemon writes tmp[len], tmp[len-1], ..., tmp[0]).
    loop {
        buf.push(tmp[len]);
        if len == 0 {
            break;
        }
        len -= 1;
    }
}

/// Read a `VarInt` at `cursor`, advance it, and return the decoded `u64`.
/// Rejects overflow past `u64::MAX`, matching the daemon.
///
/// Direct port of `ReadVarInt` at `src/serialize.h:399-417`.
pub fn read_varint_u64(buf: &[u8], cursor: &mut usize) -> Result<u64, WireError> {
    let mut n: u64 = 0;
    loop {
        let ch = read_u8(buf, cursor)?;
        if n > (u64::MAX >> 7) {
            return Err(WireError::VarIntTooLarge);
        }
        n = (n << 7) | u64::from(ch & 0x7F);
        if ch & 0x80 != 0 {
            if n == u64::MAX {
                return Err(WireError::VarIntTooLarge);
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

// --- LIMITED_STRING & var-length bytes --------------------------------------

/// Append a byte-length-prefixed byte slice: CompactSize length followed by
/// `bytes`. This is the shape used by the daemon's `std::vector<unsigned char>`
/// and `std::string` serialization (`src/serialize.h:638-690`) and by every
/// VDXF field that carries an opaque payload (`objectData`, `epk`, `ivk`, `ssk`).
pub fn write_var_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// Append a `LIMITED_STRING(s, cap)` — CompactSize length prefix + UTF-8
/// bytes, rejecting inputs longer than `cap`. Matches
/// `LimitedString<N>::Serialize` at `src/serialize.h:524`.
///
/// Cap examples from the daemon's `CDataDescriptor`: `label` is
/// `LIMITED_STRING(..., 64)`, `mimeType` is `LIMITED_STRING(..., 128)`
/// (`src/pbaas/vdxf.h:1030-1035`).
pub fn write_limited_string(buf: &mut Vec<u8>, s: &str, cap: usize) -> Result<(), WireError> {
    let bytes = s.as_bytes();
    if bytes.len() > cap {
        return Err(WireError::LimitedStringTooLong {
            cap,
            actual: bytes.len(),
        });
    }
    write_var_bytes(buf, bytes);
    Ok(())
}

// --- Primitive reads (internal) ---------------------------------------------

fn read_u8(buf: &[u8], cursor: &mut usize) -> Result<u8, WireError> {
    let b = *buf.get(*cursor).ok_or(WireError::UnexpectedEof)?;
    *cursor += 1;
    Ok(b)
}

fn read_u16_le(buf: &[u8], cursor: &mut usize) -> Result<u16, WireError> {
    let slice = buf
        .get(*cursor..*cursor + 2)
        .ok_or(WireError::UnexpectedEof)?;
    *cursor += 2;
    Ok(u16::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u32_le(buf: &[u8], cursor: &mut usize) -> Result<u32, WireError> {
    let slice = buf
        .get(*cursor..*cursor + 4)
        .ok_or(WireError::UnexpectedEof)?;
    *cursor += 4;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u64_le(buf: &[u8], cursor: &mut usize) -> Result<u64, WireError> {
    let slice = buf
        .get(*cursor..*cursor + 8)
        .ok_or(WireError::UnexpectedEof)?;
    *cursor += 8;
    Ok(u64::from_le_bytes(slice.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs_encode(n: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, n);
        buf
    }

    fn cs_roundtrip(n: u64) -> u64 {
        let bytes = cs_encode(n);
        let mut cursor = 0;
        let decoded = read_compact_size(&bytes, &mut cursor).expect("decode");
        assert_eq!(cursor, bytes.len(), "should consume all bytes");
        decoded
    }

    #[test]
    fn compact_size_boundaries_match_daemon_encoding() {
        assert_eq!(cs_encode(0), vec![0x00]);
        assert_eq!(cs_encode(0xfc), vec![0xfc]);
        assert_eq!(cs_encode(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(cs_encode(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(cs_encode(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(cs_encode(0xffff_ffff), vec![0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            cs_encode(0x1_0000_0000),
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn compact_size_round_trips_over_all_size_classes() {
        // Values above MAX_SIZE round-trip write, but read rejects them
        // (matching the daemon). They are tested separately below.
        for &n in &[
            0u64, 1, 252, 253, 0xff, 0xffff, 0x1_0000, 0x1_00_0000, MAX_SIZE,
        ] {
            assert_eq!(cs_roundtrip(n), n, "roundtrip {n}");
        }
    }

    #[test]
    fn compact_size_write_of_max_size_plus_one_is_rejected_on_read() {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, MAX_SIZE + 1);
        let mut cursor = 0;
        assert_eq!(
            read_compact_size(&buf, &mut cursor),
            Err(WireError::CompactSizeTooLarge)
        );
    }

    #[test]
    fn compact_size_rejects_non_canonical_two_byte_form() {
        // 0xfd || 0x00 0x00 — decodes to 0, but 0 must use single-byte form.
        let bytes = [0xfd, 0x00, 0x00];
        let mut c = 0;
        assert_eq!(
            read_compact_size(&bytes, &mut c),
            Err(WireError::NonCanonicalCompactSize)
        );
    }

    #[test]
    fn compact_size_rejects_non_canonical_four_byte_form() {
        // 0xfe || 0x00 0x00 0x00 0x00 — decodes to 0, illegal.
        let bytes = [0xfe, 0x00, 0x00, 0x00, 0x00];
        let mut c = 0;
        assert_eq!(
            read_compact_size(&bytes, &mut c),
            Err(WireError::NonCanonicalCompactSize)
        );
    }

    #[test]
    fn compact_size_rejects_non_canonical_eight_byte_form() {
        // 0xff || 0x00...0x00 (8 bytes) — must use shorter form.
        let bytes = [0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut c = 0;
        assert_eq!(
            read_compact_size(&bytes, &mut c),
            Err(WireError::NonCanonicalCompactSize)
        );
    }

    #[test]
    fn compact_size_rejects_values_above_max_size() {
        // MAX_SIZE + 1, encoded canonically as the 4-byte form.
        let n: u32 = (MAX_SIZE + 1) as u32;
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&n.to_le_bytes());
        let mut c = 0;
        assert_eq!(
            read_compact_size(&bytes, &mut c),
            Err(WireError::CompactSizeTooLarge)
        );
    }

    fn vi_encode(n: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varint_u64(&mut buf, n);
        buf
    }

    fn vi_roundtrip(n: u64) -> u64 {
        let bytes = vi_encode(n);
        let mut cursor = 0;
        let decoded = read_varint_u64(&bytes, &mut cursor).expect("decode");
        assert_eq!(cursor, bytes.len(), "should consume all bytes");
        decoded
    }

    /// Vectors traced from the `WriteVarInt` algorithm at
    /// `VerusCoin/src/serialize.h:382-396`. Most match the daemon's own
    /// example table at `serialize.h:357-362` verbatim, but two entries in
    /// that comment table are demonstrably wrong (they decode to different
    /// numbers when passed back through `ReadVarInt`):
    ///
    /// - `16511`: comment says `[0x80, 0xFF, 0x7F]` (3B), correct is
    ///   `[0xFF, 0x7F]` (2B). The comment even states "128-16511: 2 bytes"
    ///   on line 351, contradicting its own example. The 3-byte form
    ///   `[0x80, 0xFF, 0x7F]` decodes to 32895, not 16511.
    /// - `65535`: comment says `[0x82, 0xFD, 0x7F]`, correct is
    ///   `[0x82, 0xFE, 0x7F]`. The comment's form decodes to 65407.
    ///
    /// Worth filing upstream to VerusCoin as a docstring fix. The algorithm
    /// itself is correct — only the comment is wrong.
    #[test]
    fn varint_matches_daemon_reference_vectors() {
        assert_eq!(vi_encode(0), vec![0x00]);
        assert_eq!(vi_encode(1), vec![0x01]);
        assert_eq!(vi_encode(127), vec![0x7F]);
        assert_eq!(vi_encode(128), vec![0x80, 0x00]);
        assert_eq!(vi_encode(255), vec![0x80, 0x7F]);
        assert_eq!(vi_encode(256), vec![0x81, 0x00]);
        assert_eq!(vi_encode(16383), vec![0xFE, 0x7F]);
        assert_eq!(vi_encode(16384), vec![0xFF, 0x00]);
        assert_eq!(vi_encode(16511), vec![0xFF, 0x7F]);
        assert_eq!(vi_encode(65535), vec![0x82, 0xFE, 0x7F]);
        assert_eq!(vi_encode(1u64 << 32), vec![0x8E, 0xFE, 0xFE, 0xFF, 0x00]);
    }

    #[test]
    fn varint_flags13_and_version_encode_as_single_bytes() {
        // The two VARINT fields the outer CDataDescriptor writes are
        // version = 1 and flags = 13; both must be a single byte each,
        // because that is what the daemon-written entries produce.
        assert_eq!(vi_encode(1), vec![0x01]);
        assert_eq!(vi_encode(13), vec![0x0D]);
    }

    #[test]
    fn varint_round_trips_over_a_wide_range() {
        for &n in &[
            0u64,
            1,
            127,
            128,
            16383,
            16384,
            65535,
            1u64 << 20,
            1u64 << 32,
            u64::MAX - 1,
        ] {
            assert_eq!(vi_roundtrip(n), n, "roundtrip {n}");
        }
    }

    #[test]
    fn write_var_bytes_prefixes_with_compact_size_length() {
        let mut buf = Vec::new();
        write_var_bytes(&mut buf, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(buf, vec![0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn limited_string_within_cap_encodes_length_then_utf8() {
        let mut buf = Vec::new();
        write_limited_string(&mut buf, "ok", 64).unwrap();
        assert_eq!(buf, vec![0x02, b'o', b'k']);
    }

    #[test]
    fn limited_string_rejects_overflow_at_cap_boundary() {
        let mut buf = Vec::new();
        let long = "a".repeat(65);
        let err = write_limited_string(&mut buf, &long, 64).unwrap_err();
        assert_eq!(
            err,
            WireError::LimitedStringTooLong {
                cap: 64,
                actual: 65
            }
        );
        assert!(buf.is_empty(), "no bytes should be written on rejection");
    }

    #[test]
    fn limited_string_accepts_exact_cap_length() {
        let mut buf = Vec::new();
        let exact = "b".repeat(64);
        write_limited_string(&mut buf, &exact, 64).unwrap();
        // 0x40 = 64, then 64 bytes of 'b'.
        assert_eq!(buf[0], 0x40);
        assert_eq!(&buf[1..], exact.as_bytes());
    }
}
