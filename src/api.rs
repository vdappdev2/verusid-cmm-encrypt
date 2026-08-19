//! Public API: a single end-to-end call that produces the byte artifacts
//! a caller needs to compose a `flags:13` public-decrypt envelope entry
//! into an `updateidentity` transaction.
//!
//! Ports the daemon's `updateidentity {data:{}}` envelope handler
//! (`pbaasrpc.cpp:16042-16424`) into one Rust function. All framing and
//! crypto is done here; the caller composes the returned bytes into a
//! v4 transaction using whatever signing stack they prefer.
//!
//! Scope: the public-decrypt path. `signdata`-supplied signatures and
//! multi-value entries are out of scope. Payloads that produce an
//! `EVAL_NOTARY_EVIDENCE` output larger than `MAX_SCRIPT_ELEMENT_SIZE`
//! (6000 bytes) are transparently split across N tx outputs via
//! `CNotaryEvidence::BreakApart` (see `notary_evidence::break_apart` and
//! `block.cpp:817-842`); the daemon reassembles on read.

use ff::Field;
use group::GroupEncoding;
use jubjub::{AffinePoint, ExtendedPoint, Fr};
use rand_core::{CryptoRng, RngCore};

use crate::cc_script::write_eval_notary_evidence_script;
use crate::crypto::{aead_encrypt, kdf_sapling, sapling_ka_agree, CryptoError};
use crate::data_descriptor::{
    wrap_encrypted_with_key, write_data_descriptor, DataDescriptor,
};
use crate::data_ref::{write_cvdxf_data_ref_self_ref, SelfRefPointer};
use crate::ephemeral::{derive_epk, derive_g_d, generate_esk, EphemeralError};
use crate::notary_evidence::{
    break_apart, write_notary_evidence_for_envelope, EvidenceEntry,
};
use crate::vdxf::{write_cvdxf_data, DATA_DESCRIPTOR_KEY_LE};
use crate::wire::WireError;

/// `MAX_SCRIPT_ELEMENT_SIZE_PBAAS` (`script.h:36`) — the byte ceiling on any
/// PBaaS script element, and the trigger the daemon uses to invoke
/// `CNotaryEvidence::BreakApart` at `pbaasrpc.cpp:16405`.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 6000;

/// Safety margin the daemon adds to `baseOverhead` at `pbaasrpc.cpp:16408`
/// before subtracting it from `MAX_SCRIPT_ELEMENT_SIZE`. Absorbs the extra
/// bytes each multipart wrapper adds on top of the empty-evidence baseline
/// (chain-object header + MULTIPART type + `md` VARINTs + CompactSize).
const BREAK_APART_SAFETY_MARGIN: usize = 128;

/// Inputs to [`encrypt_public_decrypt`].
#[derive(Debug, Clone)]
pub struct EncryptRequest<'a> {
    /// Raw user payload bytes.
    pub plaintext: &'a [u8],
    /// VDXF key under which the cmm entry will be stored on the identity's
    /// `contentmultimap`. LE wire bytes; obtain via `getvdxfid <uri>` and
    /// reverse from the returned canonical BE hex.
    pub outer_vdxf_key: [u8; 20],
    /// Target chain's `ASSETCHAINS_CHAINID` in LE wire bytes. The daemon
    /// stamps this into the `CNotaryEvidence.systemID` field
    /// (`pbaasrpc.cpp:16156`).
    pub system_id: [u8; 20],
    /// Optional per-entry label. Embedded inside the encrypted payload
    /// (visible only after decrypt), matching the daemon's behaviour at
    /// `vdxf.h:1058-1059`. Max 64 UTF-8 bytes.
    pub label: Option<&'a str>,
    /// Optional MIME type. Same visibility as `label`. Max 128 bytes.
    pub mime_type: Option<&'a str>,
    /// The vout index the `EVAL_NOTARY_EVIDENCE` data-deposit output will
    /// occupy in the finished transaction. For a single-entry envelope
    /// write in the daemon's canonical layout, this is `0` (the
    /// data-deposit output precedes the identity-primary output). Callers
    /// that assemble a different tx layout supply the actual index they
    /// will use.
    pub data_deposit_vout_index: u32,
}

/// Outputs of [`encrypt_public_decrypt`]. The two byte artifacts the
/// caller consumes are `cmm_entry` (goes into `Identity.content_multimap`)
/// and `data_deposit_output_scripts` (each element goes into the tx as an
/// `EVAL_NOTARY_EVIDENCE` transparent output with `nValue = 0`, in the
/// order given, starting at `data_deposit_vout_index`).
#[derive(Debug, Clone)]
pub struct EncryptResult {
    /// `(vdxf_key, value_bytes)` pair to push into `content_multimap`.
    pub cmm_entry: ([u8; 20], Vec<u8>),
    /// One full `scriptPubKey` per `EVAL_NOTARY_EVIDENCE` transparent output
    /// the caller must add. Length 1 for payloads that fit in a single
    /// output; N for payloads that trigger `CNotaryEvidence::BreakApart`.
    /// All outputs are `nValue = 0` and must appear contiguously starting at
    /// `request.data_deposit_vout_index`; the daemon reader walks contiguous
    /// MULTIPART outputs to reassemble the original evidence.
    pub data_deposit_output_scripts: Vec<Vec<u8>>,
    /// The IVK published on-chain in the outer descriptor. Anyone with
    /// this can decrypt both AEAD layers. Exposed so callers can log,
    /// re-derive, or hand off to reader code.
    pub published_ivk: [u8; 32],
    /// The outer descriptor's `epk` field. Combined with `published_ivk`,
    /// decrypts the outer ciphertext to the wrapped CCDR pointer.
    pub outer_epk: [u8; 32],
    /// Diversifier bytes of the ephemeral Sapling address. Not required
    /// for decryption; exposed for reproducibility.
    pub ephemeral_diversifier: [u8; 11],
    /// Diversified transmission key of the ephemeral Sapling address.
    /// Not required for decryption; exposed for reproducibility.
    pub ephemeral_pk_d: [u8; 32],
}

/// Errors from [`encrypt_public_decrypt`]. Every variant maps to a
/// specific failure mode in one of the composed layers.
#[derive(Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// A field-length cap tripped during serialization (usually `label`
    /// > 64 bytes or `mime_type` > 128 bytes).
    Wire(WireError),
    /// A Sapling primitive produced an unexpected error. Should not
    /// happen for scalars/points derived by this crate; indicates a bug.
    Crypto(CryptoError),
    /// The sampled diversifier failed group_hash. Extremely rare with a
    /// working RNG — the retry loop tries up to 64 diversifiers, and each
    /// has a ~7/8 success probability.
    Ephemeral(EphemeralError),
    /// Retried the maximum number of diversifiers without finding one
    /// that decodes. Probability under a functioning RNG: `(1/8)^64` ≈
    /// `10^-58`. Effectively unreachable; surfaces only to guarantee
    /// termination.
    DiversifierSearchExhausted,
}

impl From<WireError> for EncryptError {
    fn from(e: WireError) -> Self {
        EncryptError::Wire(e)
    }
}
impl From<CryptoError> for EncryptError {
    fn from(e: CryptoError) -> Self {
        EncryptError::Crypto(e)
    }
}
impl From<EphemeralError> for EncryptError {
    fn from(e: EphemeralError) -> Self {
        EncryptError::Ephemeral(e)
    }
}

/// Maximum number of diversifiers to try before giving up. See
/// `EncryptError::DiversifierSearchExhausted`.
const DIVERSIFIER_RETRY_BUDGET: usize = 64;

/// Encrypt `request.plaintext` into a `flags:13` public-decrypt cmm entry
/// and its accompanying `EVAL_NOTARY_EVIDENCE` data-deposit output.
///
/// The RNG supplies (a) the ephemeral IVK, (b) the diversifier search,
/// and (c) the two ephemeral secret keys (one per AEAD pass). It MUST be
/// cryptographically secure — `rand::rngs::OsRng` in production; a
/// seeded `rand_chacha::ChaCha20Rng` in tests.
///
/// Produces the same byte layout the daemon emits at
/// `pbaasrpc.cpp:16042-16424` for `updateidentity {data:{...}}` when no
/// `encrypttoaddress` is supplied.
pub fn encrypt_public_decrypt<R>(
    request: &EncryptRequest<'_>,
    rng: &mut R,
) -> Result<EncryptResult, EncryptError>
where
    R: RngCore + CryptoRng,
{
    // === 1. Ephemeral Sapling recipient: sample ivk, find diversifier, derive pk_d ===
    let ivk_fr = Fr::random(&mut *rng);
    let ivk_bytes = ivk_fr.to_bytes();
    let (diversifier, g_d) = find_valid_diversifier(rng)?;
    let pk_d_ext = ExtendedPoint::from(g_d) * ivk_fr;
    let pk_d_bytes = AffinePoint::from(pk_d_ext).to_bytes();

    // === 2. Pass-1 AEAD over raw user plaintext ===
    // Produces the flags:5 CDataDescriptor that goes inside the CEvidenceData
    // dataVec on the data-deposit vout.
    let esk1 = generate_esk(rng);
    let epk1 = derive_epk(&esk1, &diversifier)?;
    let dhsecret1 = sapling_ka_agree(&esk1, &pk_d_bytes)?;
    let k1 = kdf_sapling(&dhsecret1, &epk1);
    let pass1_ciphertext = aead_encrypt(&k1, request.plaintext);

    let pass1_cdd = DataDescriptor {
        encrypted: true,
        object_data: &pass1_ciphertext,
        epk: Some(&epk1),
        version: 1,
        ..Default::default()
    };
    let mut pass1_cdd_bytes = Vec::new();
    write_data_descriptor(&mut pass1_cdd_bytes, &pass1_cdd)?;

    // === 3. Wrap pass-1 CDD in CVDXF_Data → becomes CEvidenceData.dataVec ===
    let mut ced_data_vec = Vec::new();
    write_cvdxf_data(&mut ced_data_vec, &DATA_DESCRIPTOR_KEY_LE, 1, &pass1_cdd_bytes);

    // === 4. Build CNotaryEvidence + EVAL_NOTARY_EVIDENCE scriptPubKey(s) ===
    let mut notary_evidence_bytes = Vec::new();
    write_notary_evidence_for_envelope(
        &mut notary_evidence_bytes,
        &request.system_id,
        &[EvidenceEntry {
            vdxf_key: &DATA_DESCRIPTOR_KEY_LE,
            data: &ced_data_vec,
        }],
    );
    let mut trial_script = Vec::new();
    write_eval_notary_evidence_script(&mut trial_script, &notary_evidence_bytes);
    let data_deposit_scripts = if trial_script.len() >= MAX_SCRIPT_ELEMENT_SIZE {
        // Match the daemon's threshold logic at pbaasrpc.cpp:16405-16418: split
        // the serialized CNotaryEvidence into MULTIPART chunks, each wrapped in
        // its own EVAL_NOTARY_EVIDENCE output. The reader (block.cpp:844-873)
        // walks contiguous MULTIPART outputs to reassemble.
        let empty_evidence_bytes = {
            let mut buf = Vec::new();
            write_notary_evidence_for_envelope(&mut buf, &request.system_id, &[]);
            buf
        };
        let mut empty_script = Vec::new();
        write_eval_notary_evidence_script(&mut empty_script, &empty_evidence_bytes);
        let base_overhead = empty_script.len() + BREAK_APART_SAFETY_MARGIN;
        let max_chunk_size = MAX_SCRIPT_ELEMENT_SIZE - base_overhead;
        let chunk_wrappers = break_apart(&request.system_id, &notary_evidence_bytes, max_chunk_size);
        chunk_wrappers
            .iter()
            .map(|wrapper| {
                let mut s = Vec::new();
                write_eval_notary_evidence_script(&mut s, wrapper);
                s
            })
            .collect()
    } else {
        vec![trial_script]
    };

    // === 5. Build the inner CDD that will be wrap-encrypted for the outer cmm entry ===
    // Its objectData is the CVDXFDataRef self-ref pointing at the data-deposit vout.
    // Label and mime live HERE (inside the ciphertext), matching the daemon's
    // WrapEncrypted behaviour at vdxf.h:1058-1059 where the outer's label/mime
    // are cleared after WrapEncrypted.
    let mut ccdr_bytes = Vec::new();
    write_cvdxf_data_ref_self_ref(
        &mut ccdr_bytes,
        &SelfRefPointer {
            vout_index: request.data_deposit_vout_index,
            object_num: 0,
            sub_object: 0,
        },
    );
    let inner_cdd = DataDescriptor {
        object_data: &ccdr_bytes,
        label: request.label,
        mime_type: request.mime_type,
        version: 1,
        ..Default::default()
    };

    // === 6. Pass-2: wrap-encrypt the inner CDD ===
    let esk2 = generate_esk(rng);
    let epk2 = derive_epk(&esk2, &diversifier)?;
    let dhsecret2 = sapling_ka_agree(&esk2, &pk_d_bytes)?;
    let k2 = kdf_sapling(&dhsecret2, &epk2);
    let wrapped = wrap_encrypted_with_key(&inner_cdd, &k2, &epk2)?;

    // === 7. Build the outer flags:13 CDataDescriptor ===
    // Fields: encrypted=true + epk + ivk. No label/mime — they went into the
    // wrapped inner. Flags: 1 (encrypted) | 4 (epk) | 8 (ivk) = 13.
    let outer_cdd = DataDescriptor {
        encrypted: true,
        object_data: &wrapped.object_data,
        epk: Some(&wrapped.epk),
        ivk: Some(&ivk_bytes),
        version: 1,
        ..Default::default()
    };
    let mut outer_cdd_bytes = Vec::new();
    write_data_descriptor(&mut outer_cdd_bytes, &outer_cdd)?;

    Ok(EncryptResult {
        cmm_entry: (request.outer_vdxf_key, outer_cdd_bytes),
        data_deposit_output_scripts: data_deposit_scripts,
        published_ivk: ivk_bytes,
        outer_epk: wrapped.epk,
        ephemeral_diversifier: diversifier,
        ephemeral_pk_d: pk_d_bytes,
    })
}

/// Sample random 11-byte diversifiers until one decodes under Sapling's
/// group_hash. Returns the successful `d` and its derived `g_d(d)` point.
fn find_valid_diversifier<R: RngCore>(
    rng: &mut R,
) -> Result<([u8; 11], AffinePoint), EncryptError> {
    for _ in 0..DIVERSIFIER_RETRY_BUDGET {
        let mut d = [0u8; 11];
        rng.fill_bytes(&mut d);
        if let Some(g_d) = derive_g_d(&d) {
            return Ok((d, g_d));
        }
    }
    Err(EncryptError::DiversifierSearchExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead_decrypt;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn sample_request<'a>(plaintext: &'a [u8]) -> EncryptRequest<'a> {
        EncryptRequest {
            plaintext,
            outer_vdxf_key: [0xAAu8; 20],
            system_id: [0xBBu8; 20],
            label: None,
            mime_type: None,
            data_deposit_vout_index: 0,
        }
    }

    #[test]
    fn cmm_entry_first_field_matches_request_outer_vdxf_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let req = sample_request(b"hello");
        let result = encrypt_public_decrypt(&req, &mut rng).unwrap();
        assert_eq!(result.cmm_entry.0, req.outer_vdxf_key);
    }

    #[test]
    fn outer_cdd_has_flags_13_when_no_label_or_mime() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let req = sample_request(b"hi");
        let result = encrypt_public_decrypt(&req, &mut rng).unwrap();
        // The cmm_entry bytes are a serialized CDataDescriptor.
        // Byte 0: VARINT(version=1) → 0x01
        // Byte 1: VARINT(flags) → 0x0D for flags:13.
        assert_eq!(result.cmm_entry.1[0], 0x01);
        assert_eq!(result.cmm_entry.1[1], 0x0D, "flags = 13 (encrypted | epk | ivk)");
    }

    #[test]
    fn data_deposit_script_shape_matches_eval_notary_evidence_prefix() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let req = sample_request(b"payload");
        let result = encrypt_public_decrypt(&req, &mut rng).unwrap();
        // masterParams outer push = 0x27 (39-byte push).
        assert_eq!(result.data_deposit_output_scripts[0][0], 0x27);
        // Byte 40 is OP_CHECKCRYPTOCONDITION.
        assert_eq!(result.data_deposit_output_scripts[0][40], 0xcc);
        // Last byte is OP_DROP.
        assert_eq!(*result.data_deposit_output_scripts[0].last().unwrap(), 0x75);
    }

    #[test]
    fn deterministic_output_for_same_seed() {
        let plaintext = b"deterministic test payload";
        let mut rng1 = ChaCha20Rng::seed_from_u64(42);
        let mut rng2 = ChaCha20Rng::seed_from_u64(42);
        let a = encrypt_public_decrypt(&sample_request(plaintext), &mut rng1).unwrap();
        let b = encrypt_public_decrypt(&sample_request(plaintext), &mut rng2).unwrap();
        assert_eq!(a.cmm_entry.1, b.cmm_entry.1);
        assert_eq!(a.data_deposit_output_scripts, b.data_deposit_output_scripts);
        assert_eq!(a.published_ivk, b.published_ivk);
        assert_eq!(a.outer_epk, b.outer_epk);
    }

    #[test]
    fn different_seeds_produce_different_outputs() {
        let mut rng1 = ChaCha20Rng::seed_from_u64(100);
        let mut rng2 = ChaCha20Rng::seed_from_u64(101);
        let a = encrypt_public_decrypt(&sample_request(b"same plaintext"), &mut rng1).unwrap();
        let b = encrypt_public_decrypt(&sample_request(b"same plaintext"), &mut rng2).unwrap();
        assert_ne!(a.cmm_entry.1, b.cmm_entry.1, "different seeds should diverge");
        assert_ne!(a.published_ivk, b.published_ivk);
    }

    #[test]
    fn small_payload_produces_single_data_deposit_script() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let result = encrypt_public_decrypt(&sample_request(b"tiny"), &mut rng).unwrap();
        assert_eq!(result.data_deposit_output_scripts.len(), 1);
        assert!(
            result.data_deposit_output_scripts[0].len() < MAX_SCRIPT_ELEMENT_SIZE,
            "single output must fit under MAX_SCRIPT_ELEMENT_SIZE"
        );
    }

    #[test]
    fn payload_above_threshold_produces_multiple_scripts_all_under_limit() {
        // 10 KB plaintext comfortably exceeds the single-output threshold
        // (~5.7 KB after envelope overhead) and forces BreakApart.
        let plaintext = vec![0x5Au8; 10_000];
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let result = encrypt_public_decrypt(&sample_request(&plaintext), &mut rng).unwrap();

        assert!(
            result.data_deposit_output_scripts.len() >= 2,
            "10 KB payload must chunk (got {} scripts)",
            result.data_deposit_output_scripts.len()
        );
        for (i, script) in result.data_deposit_output_scripts.iter().enumerate() {
            assert!(
                script.len() < MAX_SCRIPT_ELEMENT_SIZE,
                "chunk {i} script len {} exceeds MAX_SCRIPT_ELEMENT_SIZE",
                script.len()
            );
        }
    }

    #[test]
    fn chunked_output_still_has_a_single_cmm_entry() {
        // Only the tx outputs are split; the cmm entry (a single outer
        // CDataDescriptor) stays a single value regardless of chunk count.
        let plaintext = vec![0x77u8; 12_000];
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let result = encrypt_public_decrypt(&sample_request(&plaintext), &mut rng).unwrap();
        assert!(result.data_deposit_output_scripts.len() >= 2);
        assert_eq!(result.cmm_entry.0, [0xAAu8; 20]);
        assert_eq!(result.cmm_entry.1[0], 0x01);
        assert_eq!(result.cmm_entry.1[1], 0x0D, "flags:13 outer CDD");
    }

    #[test]
    fn label_too_long_returns_wire_error() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let long = "x".repeat(65);
        let req = EncryptRequest {
            label: Some(&long),
            ..sample_request(b"x")
        };
        let err = encrypt_public_decrypt(&req, &mut rng).unwrap_err();
        assert!(matches!(err, EncryptError::Wire(WireError::LimitedStringTooLong { .. })));
    }

    /// End-to-end self-consistency: encrypt via the public API, then
    /// decrypt the outer AEAD using only the published_ivk + outer_epk
    /// (as a reader would), and verify the plaintext is the expected
    /// CVDXF_Data-wrapped inner CDD whose objectData is the CCDR pointer
    /// to `data_deposit_vout_index`.
    #[test]
    fn outer_decrypt_recovers_expected_ccdr_pointer() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let req = EncryptRequest {
            data_deposit_vout_index: 7,
            ..sample_request(b"round-trip me")
        };
        let result = encrypt_public_decrypt(&req, &mut rng).unwrap();

        // Extract the outer CDD's objectData ciphertext.
        // Layout: 0x01 (v) | 0x0D (flags) | CompactSize(N) | N-byte ciphertext | 0x20 | epk | 0x20 | ivk
        let bytes = &result.cmm_entry.1;
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x0D);
        // CompactSize length prefix. For pass-2 ciphertexts under 253 bytes,
        // it's a single byte. `req.plaintext` is short so this is safe.
        assert!(bytes[2] < 0xFD, "expect single-byte CompactSize for this fixture");
        let cipher_len = usize::from(bytes[2]);
        let ciphertext = &bytes[3..3 + cipher_len];

        // Decrypt outer.
        let dhsecret = sapling_ka_agree(&result.published_ivk, &result.outer_epk).unwrap();
        let k = kdf_sapling(&dhsecret, &result.outer_epk);
        let plaintext = aead_decrypt(&k, ciphertext).unwrap();

        // Plaintext = CVDXF_Data(DataDescriptorKey, inner_CDD_bytes).
        assert_eq!(&plaintext[..20], &DATA_DESCRIPTOR_KEY_LE);
        assert_eq!(plaintext[20], 0x01, "CVDXF version");
        let inner_len = usize::from(plaintext[21]);
        let inner_cdd = &plaintext[22..22 + inner_len];

        // Inner CDD: 0x01 (v) | 0x00 (flags=0, since no label/mime in this test) | CompactSize(63) | 63B CCDR
        assert_eq!(inner_cdd[0], 0x01);
        assert_eq!(inner_cdd[1], 0x00, "inner flags = 0 (plaintext CCDR)");
        assert_eq!(inner_cdd[2], 0x3F, "CCDR is 63 bytes");
        let ccdr = &inner_cdd[3..3 + 63];

        // Rebuild the same CCDR from scratch and assert byte equality.
        let mut expected_ccdr = Vec::new();
        write_cvdxf_data_ref_self_ref(
            &mut expected_ccdr,
            &SelfRefPointer {
                vout_index: 7,
                object_num: 0,
                sub_object: 0,
            },
        );
        assert_eq!(ccdr, expected_ccdr.as_slice());
    }

    /// Full end-to-end: encrypt via the public API, decrypt BOTH AEAD
    /// layers with only the published_ivk, and assert we recover the
    /// original plaintext. This exercises every module composed into
    /// the API in the correct order.
    #[test]
    fn full_two_stage_decrypt_recovers_original_plaintext() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xBADFACE);
        let payload = b"the corners of Verusd contain multitudes";
        let req = sample_request(payload);
        let result = encrypt_public_decrypt(&req, &mut rng).unwrap();

        // Stage 1: outer decrypt (same as the previous test).
        let bytes = &result.cmm_entry.1;
        let cipher_len = usize::from(bytes[2]);
        let ct1 = &bytes[3..3 + cipher_len];
        let dh1 = sapling_ka_agree(&result.published_ivk, &result.outer_epk).unwrap();
        let k1 = kdf_sapling(&dh1, &result.outer_epk);
        let outer_pt = aead_decrypt(&k1, ct1).unwrap();

        // Locate the data-deposit output's inner ciphertext by parsing the
        // scriptPubKey down to the CEvidenceData dataVec.
        let script = &result.data_deposit_output_scripts[0];
        // Skip 40 bytes master push, 1 byte OP_CHECKCRYPTOCONDITION.
        // Next: OP_PUSHDATA1 or OP_PUSHDATA2 for vParams. Read the length.
        let vparams_start;
        let vparams_len;
        match script[41] {
            0x4c => {
                vparams_start = 43;
                vparams_len = usize::from(script[42]);
            }
            0x4d => {
                vparams_start = 44;
                vparams_len =
                    u16::from_le_bytes([script[42], script[43]]) as usize;
            }
            n if n < 0x4c => {
                vparams_start = 42;
                vparams_len = usize::from(n);
            }
            _ => panic!("unexpected push opcode in vparams"),
        }
        let vparams = &script[vparams_start..vparams_start + vparams_len];
        // vParams layout: push(4-byte header) | push(33-byte pubkey) | push(CNotaryEvidence)
        // = 1+4 + 1+33 = 39 bytes then the CNE push.
        assert_eq!(vparams[0], 0x04, "header push length");
        assert_eq!(vparams[5], 0x21, "pubkey push length");
        let cne_push_start = 39;
        // CNotaryEvidence push. For realistic sizes it uses OP_PUSHDATA1 or PUSHDATA2.
        let (cne_start, cne_len) = match vparams[cne_push_start] {
            0x4c => (cne_push_start + 2, usize::from(vparams[cne_push_start + 1])),
            0x4d => (
                cne_push_start + 3,
                u16::from_le_bytes([vparams[cne_push_start + 1], vparams[cne_push_start + 2]])
                    as usize,
            ),
            n if n < 0x4c => (cne_push_start + 1, usize::from(n)),
            _ => panic!("unexpected CNE push opcode"),
        };
        let cne = &vparams[cne_start..cne_start + cne_len];

        // Parse CNotaryEvidence to reach the CEvidenceData dataVec.
        // Layout: 1B v | 1B type | 20B systemID | 36B null CUTXORef | 1B state
        //       | 4B CCP version | VARINT count | 2B objType | CEvidenceData
        // CEvidenceData: 1B VARINT v | 1B VARINT v (again) | 1B VARINT type=1
        //              | 20B vdxf_key | CompactSize + dataVec
        let ced_offset = 59 + 4 + 1 + 2; // = 66
        let vdxf_offset = ced_offset + 3;
        let cs_offset = vdxf_offset + 20;
        // dataVec length is CompactSize; for realistic sizes it's OP_PUSHDATA2 form (0xFD).
        let (data_start, data_len) = if cne[cs_offset] < 0xFD {
            (cs_offset + 1, usize::from(cne[cs_offset]))
        } else {
            assert_eq!(cne[cs_offset], 0xFD);
            (
                cs_offset + 3,
                u16::from_le_bytes([cne[cs_offset + 1], cne[cs_offset + 2]]) as usize,
            )
        };
        let ced_data_vec = &cne[data_start..data_start + data_len];

        // ced_data_vec = CVDXF_Data(DataDescriptorKey, pass1_CDD_bytes).
        assert_eq!(&ced_data_vec[..20], &DATA_DESCRIPTOR_KEY_LE);
        assert_eq!(ced_data_vec[20], 0x01);
        let (pass1_start, pass1_len) = if ced_data_vec[21] < 0xFD {
            (22, usize::from(ced_data_vec[21]))
        } else {
            (
                24,
                u16::from_le_bytes([ced_data_vec[22], ced_data_vec[23]]) as usize,
            )
        };
        let pass1_cdd = &ced_data_vec[pass1_start..pass1_start + pass1_len];

        // pass1_CDD: 0x01 (v) | 0x05 (flags: encrypted|epk) | CompactSize(cipher_len)
        //          | ciphertext | 0x20 | 32B epk
        assert_eq!(pass1_cdd[0], 0x01);
        assert_eq!(pass1_cdd[1], 0x05);
        let (ct_start, ct_len) = if pass1_cdd[2] < 0xFD {
            (3, usize::from(pass1_cdd[2]))
        } else {
            (
                5,
                u16::from_le_bytes([pass1_cdd[3], pass1_cdd[4]]) as usize,
            )
        };
        let ct2 = &pass1_cdd[ct_start..ct_start + ct_len];
        let epk_prefix_off = ct_start + ct_len;
        assert_eq!(pass1_cdd[epk_prefix_off], 0x20);
        let epk1_bytes: [u8; 32] = pass1_cdd
            [epk_prefix_off + 1..epk_prefix_off + 1 + 32]
            .try_into()
            .unwrap();

        // Decrypt pass-1.
        let dh2 = sapling_ka_agree(&result.published_ivk, &epk1_bytes).unwrap();
        let k2 = kdf_sapling(&dh2, &epk1_bytes);
        let recovered = aead_decrypt(&k2, ct2).unwrap();
        assert_eq!(recovered, payload);

        // And silence the outer_pt binding — its structural correctness
        // was already tested in outer_decrypt_recovers_expected_ccdr_pointer.
        let _ = outer_pt;
    }
}
