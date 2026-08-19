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
//! objects. Two variants are supported:
//!
//! - `TYPE_DATA` — the normal payload/signature case
//! - `TYPE_MULTIPART_DATA` — used when the packed script would exceed
//!   `MAX_SCRIPT_ELEMENT_SIZE`, causing the daemon to break the whole
//!   `CNotaryEvidence` blob across N tx outputs
//!   (`CNotaryEvidence::BreakApart` at `block.cpp:817-842`).
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

/// `CEvidenceData::TYPE_DATA` (`block.h:1188`) — the standard-payload
/// serialization branch.
pub const EVIDENCE_TYPE_DATA: u32 = 1;

/// `CEvidenceData::TYPE_MULTIPART_DATA` (`block.h:1189`) — the branch
/// used to spread a serialized `CNotaryEvidence` across multiple outputs.
pub const EVIDENCE_TYPE_MULTIPART_DATA: u32 = 2;

/// `CNotaryEvidence::VERSION_CURRENT` (`block.h:2113`).
pub const NOTARY_EVIDENCE_VERSION: u8 = 1;

/// `CNotaryEvidence::TYPE_IMPORT_PROOF` (`block.h:2124`) — the type the
/// envelope path uses at `pbaasrpc.cpp:16160`.
pub const NOTARY_TYPE_IMPORT_PROOF: u8 = 3;

/// `CNotaryEvidence::TYPE_MULTIPART_DATA` (`block.h:2123`) — used to tag a
/// wrapping `CNotaryEvidence` that holds one chunk of a BrokenApart original.
pub const NOTARY_TYPE_MULTIPART_DATA: u8 = 2;

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

/// One chunk's metadata inside a `TYPE_MULTIPART_DATA` `CEvidenceData`,
/// matching `CEvidenceData::CMultiPartDescriptor` at `block.h:1167-1183`.
///
/// Values are always non-negative in a writer that constructs them from
/// physical byte offsets — the daemon declares them `int64_t` but VARINT-
/// encodes them as unsigned, and this crate never emits negatives.
#[derive(Debug, Clone, Copy)]
pub struct MultiPartDescriptor {
    /// 0-based index of this chunk among all chunks of the split payload.
    pub index: u32,
    /// Byte length of the FULL original `CNotaryEvidence` that was split.
    /// Every chunk carries the same value; readers use it to size their
    /// reassembly buffer up-front (`block.cpp:854`).
    pub total_length: u64,
    /// Byte offset at which this chunk's `data_vec` starts within the
    /// original serialized bytes (`block.cpp:865` — must equal
    /// `sum(len(chunk_i)) for i < this.index`).
    pub start: u64,
}

/// Serialize a `CEvidenceData` in its `TYPE_MULTIPART_DATA` shape
/// (`block.h:1247-1263` when `type == TYPE_MULTIPART_DATA`):
///
/// ```text
///  1B  VARINT(version=1)
///  1B  VARINT(version=1)     <- daemon quirk, see module docs
///  1B  VARINT(type=TYPE_MULTIPART_DATA=2)
///  Nb  VARINT(index)
///  Nb  VARINT(total_length)
///  Nb  VARINT(start)
///  Nb  CompactSize(chunk.len) + chunk bytes
/// ```
///
/// The 20-byte `vdxfd` present in `TYPE_DATA` is replaced by the
/// `CMultiPartDescriptor` (`block.h:1195-1199` — a union field).
pub fn write_evidence_data_multipart(
    buf: &mut Vec<u8>,
    md: &MultiPartDescriptor,
    chunk: &[u8],
) {
    write_varint_u64(buf, 1); // version
    write_varint_u64(buf, 1); // version (daemon quirk)
    write_varint_u64(buf, u64::from(EVIDENCE_TYPE_MULTIPART_DATA));
    write_varint_u64(buf, u64::from(md.index));
    write_varint_u64(buf, md.total_length);
    write_varint_u64(buf, md.start);
    write_var_bytes(buf, chunk);
}

/// Serialize a `CChainObject<CEvidenceData>` in its multipart form: 2-byte
/// object-type header followed by the `TYPE_MULTIPART_DATA` `CEvidenceData`
/// bytes.
pub fn write_evidence_data_multipart_chain_object(
    buf: &mut Vec<u8>,
    md: &MultiPartDescriptor,
    chunk: &[u8],
) {
    buf.extend_from_slice(&OBJTYPE_EVIDENCE_DATA.to_le_bytes());
    write_evidence_data_multipart(buf, md, chunk);
}

/// Serialize a full `CNotaryEvidence` in the wrapper shape used by
/// `CNotaryEvidence::BreakApart` (`block.cpp:838`) for one chunk:
///
/// - Fixed fields match `write_notary_evidence_for_envelope` EXCEPT `type`
///   is `NOTARY_TYPE_MULTIPART_DATA` instead of `NOTARY_TYPE_IMPORT_PROOF`.
/// - The `evidence` field is a `CCrossChainProof` with a single chain object
///   that is a `TYPE_MULTIPART_DATA` `CEvidenceData` carrying `chunk`.
pub fn write_notary_evidence_multipart_chunk(
    buf: &mut Vec<u8>,
    system_id: &[u8; 20],
    md: &MultiPartDescriptor,
    chunk: &[u8],
) {
    buf.push(NOTARY_EVIDENCE_VERSION);
    buf.push(NOTARY_TYPE_MULTIPART_DATA);
    buf.extend_from_slice(system_id);
    buf.extend_from_slice(&[0u8; 32]); // output hash
    buf.extend_from_slice(&[0u8; 4]); // output n
    buf.push(NOTARY_STATE_SUPPORTING);
    // CCrossChainProof: 4B version + VARINT(count=1) + one multipart chain object
    buf.extend_from_slice(&CROSS_CHAIN_PROOF_VERSION.to_le_bytes());
    write_varint_u64(buf, 1);
    write_evidence_data_multipart_chain_object(buf, md, chunk);
}

/// Split an already-serialized `CNotaryEvidence` blob into N wrapper
/// `CNotaryEvidence` blobs, each carrying one contiguous chunk of at most
/// `max_chunk_size` bytes, wrapped as a `TYPE_MULTIPART_DATA` chain object.
/// Direct port of `CNotaryEvidence::BreakApart` at `block.cpp:817-842`.
///
/// `max_chunk_size` counts the ORIGINAL byte payload per chunk — it does NOT
/// include the multipart wrapping overhead (~20-30 bytes per chunk). Callers
/// should compute it as `MAX_SCRIPT_ELEMENT_SIZE - base_overhead` where
/// `base_overhead` accounts for the wrapping and includes a safety margin.
///
/// Panics if `max_chunk_size == 0`.
pub fn break_apart(
    system_id: &[u8; 20],
    serialized_notary_evidence: &[u8],
    max_chunk_size: usize,
) -> Vec<Vec<u8>> {
    assert!(max_chunk_size > 0, "max_chunk_size must be positive");
    let total_length = serialized_notary_evidence.len() as u64;
    let mut out = Vec::new();
    let mut offset: usize = 0;
    let mut index: u32 = 0;
    while offset < serialized_notary_evidence.len() {
        let end = (offset + max_chunk_size).min(serialized_notary_evidence.len());
        let chunk = &serialized_notary_evidence[offset..end];
        let md = MultiPartDescriptor {
            index,
            total_length,
            start: offset as u64,
        };
        let mut buf = Vec::with_capacity(chunk.len() + 128);
        write_notary_evidence_multipart_chunk(&mut buf, system_id, &md, chunk);
        out.push(buf);
        offset = end;
        index += 1;
    }
    out
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
    fn multipart_evidence_data_replaces_vdxfd_with_metadata_varints() {
        let md = MultiPartDescriptor {
            index: 0,
            total_length: 1000,
            start: 0,
        };
        let chunk = [0xAAu8; 4];
        let mut buf = Vec::new();
        write_evidence_data_multipart(&mut buf, &md, &chunk);
        // 0x01 v | 0x01 v (twice) | 0x02 type=MULTIPART | VARINT(0)=0x00
        // | VARINT(1000)=0x86 0x68 | VARINT(0)=0x00 | 0x04 CompactSize + 4B
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x02, "type = TYPE_MULTIPART_DATA");
        assert_eq!(buf[3], 0x00, "VARINT(index=0)");
        assert_eq!(&buf[4..6], &[0x86, 0x68], "VARINT(total_length=1000)");
        assert_eq!(buf[6], 0x00, "VARINT(start=0)");
        assert_eq!(buf[7], 0x04, "CompactSize(chunk.len=4)");
        assert_eq!(&buf[8..12], &chunk);
        assert_eq!(buf.len(), 12);
    }

    #[test]
    fn break_apart_produces_ceil_len_over_chunk_size_wrappers() {
        let system_id = [0x11u8; 20];
        let original = vec![0xCC; 2500];
        // With chunk size 1000, expect 3 chunks: 1000 + 1000 + 500.
        let parts = break_apart(&system_id, &original, 1000);
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn break_apart_chunks_are_all_wrapper_multipart_evidence() {
        let system_id = [0x22u8; 20];
        let original = vec![0xEE; 2500];
        let parts = break_apart(&system_id, &original, 1000);
        for part in &parts {
            assert_eq!(part[0], NOTARY_EVIDENCE_VERSION, "wrapper version = 1");
            assert_eq!(
                part[1], NOTARY_TYPE_MULTIPART_DATA,
                "wrapper type = TYPE_MULTIPART_DATA"
            );
            assert_eq!(&part[2..22], &system_id, "wrapper systemID preserved");
            assert_eq!(&part[22..58], &[0u8; 36], "wrapper output = null CUTXORef");
            assert_eq!(part[58], NOTARY_STATE_SUPPORTING);
        }
    }

    #[test]
    fn break_apart_metadata_indices_and_offsets_are_sequential() {
        let system_id = [0x33u8; 20];
        let original = vec![0x77; 2500];
        let parts = break_apart(&system_id, &original, 1000);

        // Locate the CEvidenceData md inside each wrapper. Layout after the
        // 59-byte CNotaryEvidence header + CCrossChainProof(4B v + 1B count=1):
        //   offset 64: 2B objType(10) LE
        //   offset 66: 0x01 v | 0x01 v | 0x02 type(MULTIPART) | VARINT(index)
        //              | VARINT(total_length) | VARINT(start) | CompactSize + chunk
        for (i, part) in parts.iter().enumerate() {
            assert_eq!(&part[64..66], &[0x0A, 0x00], "objType = 10 (evidence data)");
            assert_eq!(part[66], 0x01);
            assert_eq!(part[67], 0x01);
            assert_eq!(part[68], 0x02, "MULTIPART type");
            // VARINT(index) — small for our test, single byte
            assert_eq!(
                u64::from(part[69]),
                i as u64,
                "md.index = wrapper index (i={i})"
            );
        }
    }

    #[test]
    fn break_apart_concatenated_chunks_recover_original() {
        // The dataVec sits at the tail of each wrapper. Reasoning: after all
        // fixed and VARINT-length prefixes, the last field is
        // `CompactSize(chunk.len) || chunk`. So the last `chunk_len` bytes of
        // each wrapper are the chunk itself; concatenated in order they must
        // equal the original serialized bytes.
        let system_id = [0x44u8; 20];
        let original = (0..2500u16).map(|i| (i & 0xFF) as u8).collect::<Vec<_>>();
        let max_chunk_size = 1000;
        let parts = break_apart(&system_id, &original, max_chunk_size);

        let mut reassembled = Vec::with_capacity(original.len());
        for (i, part) in parts.iter().enumerate() {
            let expected_chunk_len = if i + 1 == parts.len() {
                original.len() - i * max_chunk_size
            } else {
                max_chunk_size
            };
            reassembled.extend_from_slice(&part[part.len() - expected_chunk_len..]);
        }
        assert_eq!(reassembled, original);
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
