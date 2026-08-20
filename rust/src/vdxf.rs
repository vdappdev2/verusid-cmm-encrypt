//! `CVDXF` and `CVDXF_Data` framing.
//!
//! Every entry the daemon emits through `updateidentity {data:{}}` is wrapped
//! in a `CVDXF_Data` envelope: a 20-byte VDXF key + `VARINT` version + a
//! `LIMITED_VECTOR(data)` (CompactSize length prefix + raw bytes).
//!
//! Ported from `VerusCoin/src/pbaas/vdxf.h:181-257` at commit
//! `d1df9b7d254aacbc12070da48640edf84312200b`:
//!
//! ```text
//! class CVDXF {
//!     READWRITE(key);              // uint160, 20 bytes wire-order LE
//!     READWRITE(VARINT(version));  // u32, Bitcoin base-128 VarInt
//! };
//! class CVDXF_Data : public CVDXF {
//!     READWRITE(*(CVDXF *)this);
//!     if (IsValid())
//!         READWRITE(data);         // std::vector<u8> = CompactSize + bytes
//! };
//! ```
//!
//! The `IsValid()` guard is a read-side concern (skip `data` when the header
//! fails to parse). Writers always emit valid headers, so this crate emits
//! `key || VARINT(version) || CompactSize(data.len()) || data` unconditionally.

use crate::wire::{write_compact_size, write_varint_u64};

/// Default and only supported `CVDXF` version. Corresponds to
/// `CVDXF::DEFAULT_VERSION = 1` at `vdxf.h:204`.
pub const DEFAULT_VERSION: u32 = 1;

/// `DataDescriptorKey` (`i4GC1YGEVD21afWudGoFJVdnfjJ5XWnCQv`,
/// URI `vrsc::data.type.object.datadescriptor`) as 20 wire bytes.
/// This is the LE byte order — reverse for canonical BE hex display
/// (`4d4f12424ded2033a526a4e2a8835fc5b2eba208`).
///
/// This key wraps every payload the envelope path emits, both at the outer
/// cmm entry (over an encrypted `CDataDescriptor`) and at the inner
/// `signdata`-encrypted stage. Anchored empirically: the 20-byte prefix of
/// the stage-1 plaintext in `tests/fixtures/t1_578528.json` is exactly this
/// value.
pub const DATA_DESCRIPTOR_KEY_LE: [u8; 20] = [
    0x08, 0xa2, 0xeb, 0xb2, 0xc5, 0x5f, 0x83, 0xa8, 0xe2, 0xa4, 0x26, 0xa5, 0x33, 0x20, 0xed, 0x4d,
    0x42, 0x12, 0x4f, 0x4d,
];

/// `MMRDescriptorKey` (`i9dVDb4LgfMYrZD1JBNP2uaso4bNAkT4Jr`,
/// URI `vrsc::data.mmrdescriptor`) as 20 wire bytes.
/// BE hex: `97273a4c02d6be002f8d69c3979616732ba68243`.
///
/// The envelope path uses this key instead of `DataDescriptorKey` when
/// wrapping a multi-leaf MMR (`pbaasrpc.cpp:16144-16149`). All single-leaf
/// writes (the common case) use `DataDescriptorKey`.
pub const MMR_DESCRIPTOR_KEY_LE: [u8; 20] = [
    0x43, 0x82, 0xa6, 0x2b, 0x73, 0x16, 0x96, 0x97, 0xc3, 0x69, 0x8d, 0x2f, 0x00, 0xbe, 0xd6, 0x02,
    0x4c, 0x3a, 0x27, 0x97,
];

/// `SignatureDataKey` (`i7PcVF9wwPtQ6p6jDtCVpohX65pTZuP2ah`,
/// URI `vrsc::data.signaturedata`) as 20 wire bytes.
/// BE hex: `b48b359e9a00042cec64f7f66ac717d388a4f22a`.
///
/// The envelope path wraps a parallel `CDataDescriptor` under this key when
/// `signdata` produced a signature over the payload
/// (`pbaasrpc.cpp:16147-16149`). Absent for the pure public-decrypt path.
pub const SIGNATURE_DATA_KEY_LE: [u8; 20] = [
    0x2a, 0xf2, 0xa4, 0x88, 0xd3, 0x17, 0xc7, 0x6a, 0xf6, 0xf7, 0x64, 0xec, 0x2c, 0x04, 0x00, 0x9a,
    0x9e, 0x35, 0x8b, 0xb4,
];

/// `CrossChainDataRefKey` (`iP3euVSzNcXUrLNHnQnR9G6q8jeYuGSxgw`,
/// URI `vrsc::data.type.object.crosschaindataref`) as 20 wire bytes.
/// BE hex: `4d33e0aee0f648c7871b2661d1221b57c05aaed6`.
///
/// The `CVDXFDataRef` outer envelope uses this key; the envelope path
/// emits it as the CDataDescriptor's `objectData` prefix (`vdxf.h:2818`,
/// `pbaasrpc.cpp:16369`).
pub const CROSS_CHAIN_DATA_REF_KEY_LE: [u8; 20] = [
    0xd6, 0xae, 0x5a, 0xc0, 0x57, 0x1b, 0x22, 0xd1, 0x61, 0x26, 0x1b, 0x87, 0xc7, 0x48, 0xf6, 0xe0,
    0xae, 0xe0, 0x33, 0x4d,
];

/// Append a `CVDXF` header: 20 bytes of `key` (already in wire-order LE) +
/// `VARINT(version)`.
pub fn write_cvdxf_header(buf: &mut Vec<u8>, key: &[u8; 20], version: u32) {
    buf.extend_from_slice(key);
    write_varint_u64(buf, u64::from(version));
}

/// Append a `CVDXF_Data` envelope: `CVDXF` header + `CompactSize(data.len()) + data`.
pub fn write_cvdxf_data(buf: &mut Vec<u8>, key: &[u8; 20], version: u32, data: &[u8]) {
    write_cvdxf_header(buf, key, version);
    write_compact_size(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards against accidental edits to the key constants — the BE hash160
    /// hex on the right of each assertion is what `getvdxfid` returns for
    /// the URI in the constant's docstring. Reversing the LE bytes must
    /// reproduce that hex exactly.
    #[test]
    fn vdxf_key_constants_reverse_to_canonical_be_hash160() {
        assert_eq!(be_hex(&DATA_DESCRIPTOR_KEY_LE),      "4d4f12424ded2033a526a4e2a8835fc5b2eba208");
        assert_eq!(be_hex(&MMR_DESCRIPTOR_KEY_LE),       "97273a4c02d6be002f8d69c3979616732ba68243");
        assert_eq!(be_hex(&SIGNATURE_DATA_KEY_LE),       "b48b359e9a00042cec64f7f66ac717d388a4f22a");
        assert_eq!(be_hex(&CROSS_CHAIN_DATA_REF_KEY_LE), "4d33e0aee0f648c7871b2661d1221b57c05aaed6");
    }

    fn be_hex(le: &[u8; 20]) -> String {
        let mut be = *le;
        be.reverse();
        be.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn cvdxf_header_is_key_bytes_then_varint_version() {
        let mut buf = Vec::new();
        write_cvdxf_header(&mut buf, &DATA_DESCRIPTOR_KEY_LE, 1);
        let mut expected = DATA_DESCRIPTOR_KEY_LE.to_vec();
        expected.push(0x01); // VARINT(1) = single byte 0x01
        assert_eq!(buf, expected);
    }

    #[test]
    fn cvdxf_data_is_header_then_compact_size_then_bytes() {
        let mut buf = Vec::new();
        write_cvdxf_data(&mut buf, &DATA_DESCRIPTOR_KEY_LE, 1, &[0xAB, 0xCD]);
        let mut expected = DATA_DESCRIPTOR_KEY_LE.to_vec();
        expected.push(0x01); // VARINT(version=1)
        expected.push(0x02); // CompactSize(len=2)
        expected.extend_from_slice(&[0xAB, 0xCD]);
        assert_eq!(buf, expected);
    }

    #[test]
    fn cvdxf_data_encodes_zero_length_payload_as_header_plus_00() {
        let mut buf = Vec::new();
        write_cvdxf_data(&mut buf, &DATA_DESCRIPTOR_KEY_LE, 1, &[]);
        let mut expected = DATA_DESCRIPTOR_KEY_LE.to_vec();
        expected.push(0x01); // VARINT version
        expected.push(0x00); // CompactSize length = 0
        assert_eq!(buf, expected);
    }

    #[test]
    fn cvdxf_data_encodes_252_byte_payload_with_single_byte_length_prefix() {
        // 252 = 0xFC = largest value that fits in the 1-byte CompactSize form.
        let payload = vec![0x77u8; 252];
        let mut buf = Vec::new();
        write_cvdxf_data(&mut buf, &DATA_DESCRIPTOR_KEY_LE, 1, &payload);
        assert_eq!(buf.len(), 20 + 1 + 1 + 252);
        assert_eq!(buf[21], 0xFC, "252 fits in single-byte CompactSize");
        assert_eq!(&buf[22..], payload.as_slice());
    }

    #[test]
    fn cvdxf_data_encodes_253_byte_payload_with_three_byte_length_prefix() {
        // 253 crosses into the 0xfd || u16 CompactSize form.
        let payload = vec![0x88u8; 253];
        let mut buf = Vec::new();
        write_cvdxf_data(&mut buf, &DATA_DESCRIPTOR_KEY_LE, 1, &payload);
        assert_eq!(buf.len(), 20 + 1 + 3 + 253);
        assert_eq!(&buf[21..24], &[0xFD, 0xFD, 0x00]);
        assert_eq!(&buf[24..], payload.as_slice());
    }
}
