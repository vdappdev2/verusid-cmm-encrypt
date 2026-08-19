//! `CNotaryEvidence` + `CCrossChainProof` + `CEvidenceData` — the payload
//! bytes carried by every `EVAL_NOTARY_EVIDENCE` data-deposit output the
//! envelope path emits (`pbaasrpc.cpp:16353-16357`).
//!
//! Ported from `VerusCoin/src/primitives/block.h`:
//!
//! - `CBaseChainObject` / `CChainObject<T>` — lines 962-1005
//! - `CEvidenceData` — lines 1157-1288
//! - `CCrossChainProof` — lines 1292-1605 (write path at 1502-1511)
//! - `CNotaryEvidence` — lines 2106-2405
//!
//! Envelope-writer variant only. All other chain-object types
//! (`CHAINOBJ_HEADER`, `CHAINOBJ_TRANSACTION_PROOF`, etc.) are out of scope
//! — the envelope path exclusively emits `CEvidenceData` (type 10) chain
//! objects. Similarly `TYPE_MULTIPART_DATA` on `CEvidenceData` is deferred
//! to Phase 2 (chunking).
//!
//! ## CEvidenceData quirk: version is serialized TWICE
//!
//! `CEvidenceData::SerializationOp` (`block.h:1247-1249`) contains:
//!
//! ```cpp
//! READWRITE(VARINT(version));
//! READWRITE(VARINT(version));  // <- yes, twice
//! ```
//!
//! The daemon writes the VARINT-encoded version field back-to-back. The
//! reader consumes both and the second value wins. This looks like an
//! upstream mistake — but byte-parity requires we reproduce it exactly.
//! See `reference_cevidencedata_double_version_serialization` memory.

use crate::wire::{write_compact_size, write_var_bytes, write_varint_u64};

/// `CBaseChainObject::objectType` for `CEvidenceData` (`block.h:829`).
pub const OBJTYPE_EVIDENCE_DATA: u16 = 10;

/// `CEvidenceData::TYPE_DATA` (`block.h:1188`) — the only variant the
/// envelope writer emits.
pub const EVIDENCE_TYPE_DATA: u32 = 1;

/// `CNotaryEvidence::VERSION_CURRENT` (`block.h:2113`).
pub const NOTARY_EVIDENCE_VERSION: u8 = 1;

/// `CNotaryEvidence::TYPE_IMPORT_PROOF` (`block.h:2124`) — the type the
/// envelope path uses at `pbaasrpc.cpp:16160`.
pub const NOTARY_TYPE_IMPORT_PROOF: u8 = 3;

/// `CNotaryEvidence::STATE_SUPPORTING` (`block.h:2130`) — the state the
/// envelope path uses at `pbaasrpc.cpp:16159`.
pub const NOTARY_STATE_SUPPORTING: u8 = 2;

/// `CCrossChainProof::VERSION_CURRENT` (`block.h:1299`).
pub const CROSS_CHAIN_PROOF_VERSION: u32 = 1;

/// One payload entry inside a `CCrossChainProof`. Envelope writes emit one
/// (for the encrypted `CVDXF_Data`-wrapped `CDataDescriptor`) or two (adds
/// a signature `CVDXF_Data` when `signdata` produced one).
#[derive(Debug, Clone, Copy)]
pub struct EvidenceEntry<'a> {
    /// VDXF key stored in `CEvidenceData.vdxfd` (`block.h:1198`). For the
    /// envelope path this is `DATA_DESCRIPTOR_KEY_LE` for the payload
    /// entry and `SIGNATURE_DATA_KEY_LE` for the optional signature entry
    /// (`pbaasrpc.cpp:16159-16161`).
    pub vdxf_key: &'a [u8; 20],
    /// The serialized `CVDXF_Data(vdxf_key, ...)` bytes that go in
    /// `CEvidenceData.dataVec`.
    pub data: &'a [u8],
}

/// Serialize a single `CEvidenceData` in its `TYPE_DATA` shape.
///
/// Wire layout (`block.h:1247-1262`):
///
/// ```text
///  1B  VARINT(version=1)
///  1B  VARINT(version=1)     <- daemon quirk, see module docs
///  1B  VARINT(type=TYPE_DATA=1)
/// 20B  vdxfd (LE)
///  Nb  CompactSize(dataVec.len) + dataVec
/// ```
pub fn write_evidence_data(buf: &mut Vec<u8>, entry: &EvidenceEntry<'_>) {
    write_varint_u64(buf, 1); // version
    write_varint_u64(buf, 1); // version (again — matches daemon serialization)
    write_varint_u64(buf, u64::from(EVIDENCE_TYPE_DATA));
    buf.extend_from_slice(entry.vdxf_key);
    write_var_bytes(buf, entry.data);
}

/// Serialize a `CChainObject<CEvidenceData>`: 2-byte object-type header
/// (`CBaseChainObject::objectType` at `block.h:965`) followed by the
/// `CEvidenceData` bytes.
pub fn write_evidence_data_chain_object(buf: &mut Vec<u8>, entry: &EvidenceEntry<'_>) {
    buf.extend_from_slice(&OBJTYPE_EVIDENCE_DATA.to_le_bytes());
    write_evidence_data(buf, entry);
}

/// Serialize a `CCrossChainProof` containing `entries.len()` chain
/// objects, each being a `CEvidenceData` of type `TYPE_DATA`.
///
/// Wire layout (`block.h:1332-1511`):
///
/// ```text
///  4B  uint32 LE version
///  Nb  VARINT(chainObjects.size)
///  Nb  N × CChainObject<CEvidenceData>
/// ```
pub fn write_cross_chain_proof(buf: &mut Vec<u8>, entries: &[EvidenceEntry<'_>]) {
    buf.extend_from_slice(&CROSS_CHAIN_PROOF_VERSION.to_le_bytes());
    write_varint_u64(buf, entries.len() as u64);
    for entry in entries {
        write_evidence_data_chain_object(buf, entry);
    }
}

/// Serialize a full `CNotaryEvidence` in its envelope-writer shape
/// (`pbaasrpc.cpp:16156-16161`).
///
/// Fixed fields:
///
/// - `version = 1`, `type = TYPE_IMPORT_PROOF (3)`, `state = STATE_SUPPORTING (2)`
/// - `output = CUTXORef(uint256(0), 0)` — all 36 bytes zero (self-referring)
///
/// Caller supplies:
///
/// - `system_id` — 20-byte `ASSETCHAINS_CHAINID` in wire-order LE
/// - `entries` — the payload (and optional signature) evidence data
///
/// Wire layout (`block.h:2179-2187`):
///
/// ```text
///  1B  version
///  1B  type
/// 20B  systemID (LE)
/// 36B  output (32B hash + 4B n LE)
///  1B  state
///  Nb  CCrossChainProof
/// ```
pub fn write_notary_evidence_for_envelope(
    buf: &mut Vec<u8>,
    system_id: &[u8; 20],
    entries: &[EvidenceEntry<'_>],
) {
    buf.push(NOTARY_EVIDENCE_VERSION);
    buf.push(NOTARY_TYPE_IMPORT_PROOF);
    buf.extend_from_slice(system_id);
    buf.extend_from_slice(&[0u8; 32]); // hash
    buf.extend_from_slice(&[0u8; 4]); // n
    buf.push(NOTARY_STATE_SUPPORTING);
    write_cross_chain_proof(buf, entries);
}

/// Same as `write_var_bytes` but exposed so tests can rebuild inputs
/// that match the daemon's `dataVec` framing.
pub fn write_data_vec_length_prefix(buf: &mut Vec<u8>, len: usize) {
    write_compact_size(buf, len as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_DESCRIPTOR_KEY_LE: [u8; 20] = crate::vdxf::DATA_DESCRIPTOR_KEY_LE;
    const SIGNATURE_DATA_KEY_LE: [u8; 20] = crate::vdxf::SIGNATURE_DATA_KEY_LE;

    #[test]
    fn evidence_data_writes_version_twice() {
        // Regression against the daemon quirk: version field appears twice.
        let entry = EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: &[0xAA],
        };
        let mut buf = Vec::new();
        write_evidence_data(&mut buf, &entry);
        assert_eq!(buf[0], 0x01, "first VARINT(version)");
        assert_eq!(buf[1], 0x01, "second VARINT(version) — daemon quirk");
        assert_eq!(buf[2], 0x01, "VARINT(type=TYPE_DATA)");
        assert_eq!(&buf[3..23], &DATA_DESCRIPTOR_KEY_LE);
        assert_eq!(&buf[23..], &[0x01, 0xAA]); // CompactSize(1) + data
    }

    #[test]
    fn evidence_data_chain_object_prefixes_with_2b_le_type_10() {
        let entry = EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: &[],
        };
        let mut buf = Vec::new();
        write_evidence_data_chain_object(&mut buf, &entry);
        // 2 bytes = 0x0A 0x00 (uint16 LE for objType=10)
        assert_eq!(&buf[..2], &[0x0A, 0x00]);
    }

    #[test]
    fn cross_chain_proof_encodes_zero_objects_as_version_and_zero_count() {
        let mut buf = Vec::new();
        write_cross_chain_proof(&mut buf, &[]);
        assert_eq!(buf, vec![0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn cross_chain_proof_encodes_two_entries_in_order() {
        let payload = EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: &[0xAA],
        };
        let signature = EvidenceEntry {
            vdxf_key: &SIGNATURE_DATA_KEY_LE,
            data: &[0xBB, 0xCC],
        };
        let mut buf = Vec::new();
        write_cross_chain_proof(&mut buf, &[payload, signature]);

        // Version (4B LE) | VARINT(count=2) | two chain objects
        assert_eq!(&buf[..4], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(buf[4], 0x02); // VARINT count
        // Payload chain object starts at offset 5 with 0x0A 0x00 type header.
        assert_eq!(&buf[5..7], &[0x0A, 0x00]);
        // Payload's vdxf key is DataDescriptorKey after 3 VARINTs.
        assert_eq!(&buf[10..30], &DATA_DESCRIPTOR_KEY_LE);
        // Signature chain object follows. Payload size: 2 (type hdr) + 3
        // (VARINTs) + 20 (key) + 2 (CompactSize + 1B data) = 27 → sig starts at 5+27 = 32.
        assert_eq!(&buf[32..34], &[0x0A, 0x00]);
        assert_eq!(&buf[37..57], &SIGNATURE_DATA_KEY_LE);
    }

    #[test]
    fn notary_evidence_for_envelope_produces_correct_fixed_prefix() {
        let system_id = [0xAA; 20];
        let mut buf = Vec::new();
        write_notary_evidence_for_envelope(&mut buf, &system_id, &[]);

        assert_eq!(buf[0], NOTARY_EVIDENCE_VERSION, "version = 1");
        assert_eq!(buf[1], NOTARY_TYPE_IMPORT_PROOF, "type = 3");
        assert_eq!(&buf[2..22], &system_id);
        assert_eq!(&buf[22..58], &[0u8; 36], "36 zero bytes for null CUTXORef");
        assert_eq!(buf[58], NOTARY_STATE_SUPPORTING, "state = 2");
        // Remainder is empty CCrossChainProof: 4B version + 1B count(0) = 5 bytes.
        assert_eq!(&buf[59..], &[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn notary_evidence_length_grows_by_entry_overhead() {
        // Overhead per entry: 2B chain header + 24B CEvidenceData framing (3 VARINTs + 20B key + CompactSize)
        // = 26B minimum + data.
        let entry = EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: &[0u8; 100],
        };
        let mut buf = Vec::new();
        write_notary_evidence_for_envelope(&mut buf, &[0; 20], &[entry]);
        // Base (empty proof) = 64; add 2B objType + 3B VARINTs + 20B key + 1B CS + 100B data = 126.
        // Total = 64 + 126 = 190. But CompactSize(100) is 1 byte (< 253).
        assert_eq!(buf.len(), 190);
    }
}
