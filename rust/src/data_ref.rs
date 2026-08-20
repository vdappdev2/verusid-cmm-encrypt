//! `CVDXFDataRef` self-ref pointer — the 63-byte structure that lives
//! inside a plaintext `CDataDescriptor.objectData` on the outer envelope
//! entry, pointing at the `EVAL_NOTARY_EVIDENCE` data-deposit output on the
//! same transaction.
//!
//! Ported from:
//!
//! - `CPBaaSEvidenceRef` — `VerusCoin/src/primitives/block.h:2427-2516`
//! - `CCrossChainDataRef` — `block.h:2683-2805`
//! - `CVDXFDataRef` — `block.h:2807-2873`
//!
//! Only the self-referring evidence variant (`CCrossChainDataRef` type tag
//! `TYPE_CROSSCHAIN_DATAREF = 0` wrapping a `CPBaaSEvidenceRef` with
//! null hash and `FLAG_ISEVIDENCE` set) is emitted by the envelope writer.
//! The `IDENTITY_DATAREF` and `URL_REF` variants are out of scope for this
//! crate (they can be added later; each is a separate composition).
//!
//! Wire layout for the full 63-byte outer:
//!
//! ```text
//! 20B CrossChainDataRefKey (LE)         <- CVDXF header key
//!  1B VARINT version = 1
//!  1B CompactSize length prefix = 41
//! 41B CCrossChainDataRef {
//!     1B type tag = 0x00 (TYPE_CROSSCHAIN_DATAREF)
//!    40B CPBaaSEvidenceRef {
//!        1B VARINT version = 1
//!        1B VARINT flags = 1 (FLAG_ISEVIDENCE, no HAS_SYSTEM, no HAS_HASH)
//!       32B hash = all zeros (self-ref)
//!        4B nIn (u32 LE) = vout index of the data-deposit output
//!        1B VARINT objectNum
//!        1B VARINT subObject
//!    }
//! }
//! ```
//!
//! Two size subtleties vs a naive read:
//!
//! - `nIn` at `block.h:340` is `READWRITE(n)` on a bare `uint32_t`, so it
//!   is a fixed 4-byte little-endian field, **not** a VARINT.
//! - `hash` on `CUTXORef` / `COutPoint` is a `uint256`, which the daemon
//!   serializes as raw wire-order LE 32 bytes.

use crate::vdxf::{write_cvdxf_data, CROSS_CHAIN_DATA_REF_KEY_LE};
use crate::wire::write_varint_u64;

/// `CPBaaSEvidenceRef::FLAG_ISEVIDENCE` (`block.h:2431`). Always set for
/// envelope writes; `SetFlags` at `block.h:2465-2476` preserves this bit
/// and derives the other two flags from field presence.
pub const FLAG_ISEVIDENCE: u32 = 1;

/// `CCrossChainDataRef::TYPE_CROSSCHAIN_DATAREF` (`block.h:2687`). Type
/// tag for the envelope writer's variant.
pub const TYPE_CROSSCHAIN_DATAREF: u8 = 0;

/// The three integer fields that vary per envelope entry. All other
/// `CPBaaSEvidenceRef` fields (version, flags, hash, systemID, dataHash)
/// are fixed for the self-ref shape.
#[derive(Debug, Clone, Copy)]
pub struct SelfRefPointer {
    /// Index of the `EVAL_NOTARY_EVIDENCE` data-deposit output on the same
    /// transaction. Serializes as 4 bytes little-endian.
    pub vout_index: u32,
    /// `objectNum` — index of the payload chain-object within the
    /// referenced `CNotaryEvidence`. `0` for envelope writes
    /// (`pbaasrpc.cpp:16369`).
    pub object_num: u32,
    /// `subObject` — payload vs signature descriptor selector. `0` for the
    /// payload descriptor, `1` for the signature descriptor when signdata
    /// produced one (`pbaasrpc.cpp:16382`).
    pub sub_object: u32,
}

/// Serialize a bare `CPBaaSEvidenceRef` self-ref (40 bytes). Innermost
/// layer; useful as a testable primitive.
pub fn write_pbaas_evidence_ref_self_ref(buf: &mut Vec<u8>, ptr: &SelfRefPointer) {
    write_varint_u64(buf, 1); // version
    write_varint_u64(buf, u64::from(FLAG_ISEVIDENCE)); // flags = 1

    // CUTXORef output: 32B hash (all zeros) + 4B nIn LE.
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(&ptr.vout_index.to_le_bytes());

    write_varint_u64(buf, u64::from(ptr.object_num));
    write_varint_u64(buf, u64::from(ptr.sub_object));
}

/// Serialize a `CCrossChainDataRef` self-ref (41 bytes = 1B type tag +
/// 40B evidence ref).
pub fn write_cross_chain_data_ref_self_ref(buf: &mut Vec<u8>, ptr: &SelfRefPointer) {
    buf.push(TYPE_CROSSCHAIN_DATAREF);
    write_pbaas_evidence_ref_self_ref(buf, ptr);
}

/// Serialize the full 63-byte `CVDXFDataRef` self-ref: the outer CVDXF
/// envelope wrapping the CCrossChainDataRef via a CompactSize length
/// prefix. This is the byte string that becomes the outer envelope's inner
/// `CDataDescriptor.objectData` (`pbaasrpc.cpp:16369-16371`).
pub fn write_cvdxf_data_ref_self_ref(buf: &mut Vec<u8>, ptr: &SelfRefPointer) {
    let mut inner = Vec::with_capacity(41);
    write_cross_chain_data_ref_self_ref(&mut inner, ptr);
    write_cvdxf_data(buf, &CROSS_CHAIN_DATA_REF_KEY_LE, 1, &inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbaas_evidence_ref_self_ref_vout0_is_40_bytes_and_matches_expected() {
        let mut buf = Vec::new();
        write_pbaas_evidence_ref_self_ref(
            &mut buf,
            &SelfRefPointer {
                vout_index: 0,
                object_num: 0,
                sub_object: 0,
            },
        );
        assert_eq!(buf.len(), 40);
        // Expected: 0x01 (VARINT v=1) 0x01 (VARINT flags=1) 32B zeros 4B zeros 0x00 0x00
        let mut expected = vec![0x01, 0x01];
        expected.extend_from_slice(&[0u8; 32]);
        expected.extend_from_slice(&[0u8; 4]);
        expected.push(0x00);
        expected.push(0x00);
        assert_eq!(buf, expected);
    }

    #[test]
    fn pbaas_evidence_ref_encodes_nin_as_fixed_4_byte_little_endian() {
        // 0x12345678 LE = 78 56 34 12
        let mut buf = Vec::new();
        write_pbaas_evidence_ref_self_ref(
            &mut buf,
            &SelfRefPointer {
                vout_index: 0x1234_5678,
                object_num: 0,
                sub_object: 0,
            },
        );
        // nIn starts at offset 2 + 32 = 34.
        assert_eq!(&buf[34..38], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn cross_chain_data_ref_self_ref_is_type_tag_plus_evidence() {
        let mut buf = Vec::new();
        write_cross_chain_data_ref_self_ref(
            &mut buf,
            &SelfRefPointer {
                vout_index: 0,
                object_num: 0,
                sub_object: 0,
            },
        );
        assert_eq!(buf.len(), 41);
        assert_eq!(buf[0], TYPE_CROSSCHAIN_DATAREF);
    }

    #[test]
    fn cvdxf_data_ref_self_ref_produces_63_bytes_with_correct_key_and_length() {
        let mut buf = Vec::new();
        write_cvdxf_data_ref_self_ref(
            &mut buf,
            &SelfRefPointer {
                vout_index: 0,
                object_num: 0,
                sub_object: 0,
            },
        );
        assert_eq!(buf.len(), 63);
        assert_eq!(&buf[..20], &CROSS_CHAIN_DATA_REF_KEY_LE);
        assert_eq!(buf[20], 0x01, "VARINT version");
        assert_eq!(buf[21], 0x29, "CompactSize length = 41");
    }

    #[test]
    fn cvdxf_data_ref_self_ref_matches_expected_byte_pattern_for_signature_descriptor() {
        // The second-descriptor branch in the envelope path uses sub_object=1.
        let mut buf = Vec::new();
        write_cvdxf_data_ref_self_ref(
            &mut buf,
            &SelfRefPointer {
                vout_index: 3,
                object_num: 0,
                sub_object: 1,
            },
        );
        assert_eq!(buf.len(), 63);
        // Sub-object appears as the last byte of the CPBaaSEvidenceRef, at
        // offset 20 (key) + 1 (v) + 1 (CompactSize) + 1 (type) + 1 (v) + 1 (flags) + 32 (hash) + 4 (nIn) + 1 (objectNum) = 62
        assert_eq!(buf[62], 0x01, "sub_object = 1 (VARINT single byte)");
        // vout_index bytes at offset 20+1+1+1+1+1+32 = 57
        assert_eq!(&buf[57..61], &[0x03, 0x00, 0x00, 0x00]);
    }
}
