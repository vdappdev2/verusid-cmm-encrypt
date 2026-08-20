//! CryptoCondition scriptPubKey builder for `EVAL_NOTARY_EVIDENCE`
//! data-deposit outputs.
//!
//! Ported from:
//!
//! - `MakeMofNCCScript` — `VerusCoin/src/cc/CCinclude.h:97-112`
//! - `COptCCParams::AsVector` — `src/script/standard.cpp:203-222`
//! - `CScript::operator<<(vector<u8>)` push-encoding — `src/script/script.h:560-587`
//! - Well-known CC pubkey — `src/cc/CCcustom.cpp:61`
//!   (`NotaryEvidencePubKey = "03e1894e...eb5a2d9"`)
//! - `EVAL_NOTARY_EVIDENCE` eval code — `src/cc/eval.h:44` (`0x03`)
//!
//! Envelope-writer scope: single condition, 1-of-1, pay-to-pubkey using the
//! well-known CC pubkey, with a `CNotaryEvidence` blob as the sole data
//! parameter. Wire shape:
//!
//! ```text
//!  push(39B masterParams)         <- 1-byte push length (0x27)
//!    header:  04 03 00 01 01      <- push(4-byte {v=3, eval=0, m=1, n=1})
//!    pubkey:  21 <33B CC pubkey>  <- push(33-byte compressed PK)
//!  OP_CHECKCRYPTOCONDITION (0xcc)
//!  push(vParams)                  <- OP_PUSHDATA2 with 2-byte LE size (for typical envelope sizes)
//!    header:  04 03 03 01 01      <- push(4-byte {v=3, eval=3, m=1, n=1})
//!    pubkey:  21 <33B CC pubkey>
//!    data:    <push prefix> <serialized CNotaryEvidence>
//!  OP_DROP (0x75)
//! ```
//!
//! The well-known CC pubkey is a hardcoded constant per eval code
//! (`CCinit` at `CCcustom.cpp:219-227` copies it verbatim from
//! `NotaryEvidencePubKey`); it does not vary by chain or by tx.

/// `EVAL_NOTARY_EVIDENCE` from `cc/eval.h:44`.
pub const EVAL_NOTARY_EVIDENCE: u8 = 0x03;

/// `EVAL_NONE` — used by the master params of a `MakeMofNCCScript` v3 wrap.
pub const EVAL_NONE: u8 = 0x00;

/// `COptCCParams::VERSION_V3` (`script.h:386`).
pub const COPT_CC_PARAMS_VERSION_V3: u8 = 3;

/// The well-known CC pubkey for `EVAL_NOTARY_EVIDENCE`.
/// Hardcoded at `VerusCoin/src/cc/CCcustom.cpp:61` as
/// `NotaryEvidencePubKey = "03e1894e...eb5a2d9"`. Compressed secp256k1.
pub const NOTARY_EVIDENCE_CC_PUBKEY: [u8; 33] = [
    0x03, 0xe1, 0x89, 0x4e, 0x9d, 0x48, 0x71, 0x25, 0xbe, 0x5a, 0x8c, 0x66, 0x57, 0xa8, 0xce, 0x01,
    0xbc, 0x81, 0xba, 0x78, 0x16, 0xd6, 0x98, 0xdb, 0xfc, 0xfb, 0x04, 0x83, 0x75, 0x4e, 0xb5, 0xa2,
    0xd9,
];

/// `OP_PUSHDATA1` — `script/script.h`.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2` — `script/script.h`.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// `OP_PUSHDATA4` — `script/script.h`.
pub const OP_PUSHDATA4: u8 = 0x4e;
/// `OP_CHECKCRYPTOCONDITION` — the CC-specific opcode.
pub const OP_CHECKCRYPTOCONDITION: u8 = 0xcc;
/// `OP_DROP`.
pub const OP_DROP: u8 = 0x75;

/// Append a Bitcoin-script data push of `data`. Matches
/// `CScript::operator<<(vector<u8>)` at `script.h:560-587`:
///
/// - `len < 0x4c` → 1-byte length prefix
/// - `len <= 0xff` → `OP_PUSHDATA1 || 1-byte length`
/// - `len <= 0xffff` → `OP_PUSHDATA2 || u16 LE length`
/// - else → `OP_PUSHDATA4 || u32 LE length`
pub fn write_push(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < usize::from(OP_PUSHDATA1) {
        buf.push(len as u8);
    } else if len <= usize::from(u8::MAX) {
        buf.push(OP_PUSHDATA1);
        buf.push(len as u8);
    } else if len <= usize::from(u16::MAX) {
        buf.push(OP_PUSHDATA2);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        buf.push(OP_PUSHDATA4);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    }
    buf.extend_from_slice(data);
}

/// Serialize a `COptCCParams` in the shape used by the envelope-writer's
/// v3 single-pubkey scripts (`standard.cpp:203-222`).
///
/// Layout as bytes:
///
/// - `push(4-byte {version, evalCode, m, n})`
/// - `push(33-byte compressed CC pubkey)`
/// - `push(data)` for each data blob in `data`
///
/// The pubkey is stored without the 1-byte address-type prefix that v3
/// applies to non-PK destinations, because the well-known CC pubkey is an
/// `ADDRTYPE_PK` which the daemon exempts (`standard.cpp:211-213`).
pub fn write_v3_opt_cc_params_pk(
    buf: &mut Vec<u8>,
    eval_code: u8,
    m: u8,
    n: u8,
    pubkey: &[u8; 33],
    data: &[&[u8]],
) {
    let mut params = Vec::with_capacity(40 + data.iter().map(|d| d.len() + 3).sum::<usize>());
    write_push(&mut params, &[COPT_CC_PARAMS_VERSION_V3, eval_code, m, n]);
    write_push(&mut params, pubkey);
    for d in data {
        write_push(&mut params, d);
    }
    write_push(buf, &params);
}

/// Full scriptPubKey for an `EVAL_NOTARY_EVIDENCE` data-deposit output
/// (`pbaasrpc.cpp:16353-16357`, `CCinclude.h:97-112`).
///
/// Layout:
///
/// ```text
/// push(masterParams: v=3, eval=0, m=1, n=1, keys=[ccPubkey], data=[])
/// OP_CHECKCRYPTOCONDITION
/// push(vParams:      v=3, eval=3, m=1, n=1, keys=[ccPubkey], data=[notary_evidence])
/// OP_DROP
/// ```
pub fn write_eval_notary_evidence_script(buf: &mut Vec<u8>, notary_evidence: &[u8]) {
    // Master params: eval=0 (EVAL_NONE), no data blob.
    write_v3_opt_cc_params_pk(buf, EVAL_NONE, 1, 1, &NOTARY_EVIDENCE_CC_PUBKEY, &[]);
    buf.push(OP_CHECKCRYPTOCONDITION);
    // Actual condition: eval=3 (EVAL_NOTARY_EVIDENCE), with the notary evidence as sole data.
    write_v3_opt_cc_params_pk(
        buf,
        EVAL_NOTARY_EVIDENCE,
        1,
        1,
        &NOTARY_EVIDENCE_CC_PUBKEY,
        &[notary_evidence],
    );
    buf.push(OP_DROP);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_push_uses_single_byte_prefix_below_0x4c() {
        let mut buf = Vec::new();
        write_push(&mut buf, &[0xAA; 75]);
        assert_eq!(buf[0], 0x4B, "len=75 = 0x4B");
        assert_eq!(buf.len(), 1 + 75);
    }

    #[test]
    fn write_push_uses_pushdata1_at_boundary() {
        let mut buf = Vec::new();
        write_push(&mut buf, &[0xAA; 76]);
        // 76 = 0x4C = OP_PUSHDATA1, so must switch to two-byte prefix form.
        assert_eq!(buf[0], OP_PUSHDATA1);
        assert_eq!(buf[1], 76);
        assert_eq!(buf.len(), 2 + 76);
    }

    #[test]
    fn write_push_uses_pushdata2_above_255() {
        let mut buf = Vec::new();
        let data = vec![0xBBu8; 256];
        write_push(&mut buf, &data);
        assert_eq!(buf[0], OP_PUSHDATA2);
        assert_eq!(&buf[1..3], &[0x00, 0x01], "256 LE = 0x00 0x01");
        assert_eq!(buf.len(), 3 + 256);
    }

    #[test]
    fn v3_opt_cc_params_master_has_expected_39_byte_length() {
        // Master params for the envelope path: eval=0, m=1, n=1, 33B pubkey, no data.
        // Inner AsVector = push(4B header) + push(33B pubkey) = 5 + 34 = 39.
        // Outer push adds 1 (single-byte length prefix), total = 40 bytes.
        let mut buf = Vec::new();
        write_v3_opt_cc_params_pk(&mut buf, EVAL_NONE, 1, 1, &NOTARY_EVIDENCE_CC_PUBKEY, &[]);
        assert_eq!(buf.len(), 40);
        assert_eq!(buf[0], 0x27, "outer push length = 39 = 0x27");
        // Inner starts at offset 1.
        assert_eq!(buf[1], 0x04, "header push length = 4");
        assert_eq!(&buf[2..6], &[0x03, 0x00, 0x01, 0x01], "v=3, eval=0, m=1, n=1");
        assert_eq!(buf[6], 0x21, "pubkey push length = 33 = 0x21");
        assert_eq!(&buf[7..40], &NOTARY_EVIDENCE_CC_PUBKEY);
    }

    #[test]
    fn eval_notary_evidence_script_layout_at_realistic_size() {
        // For a 360B CNotaryEvidence (per fixture), full scriptPubKey is 447 bytes:
        // 40 (master push) + 1 (OP_CHECKCRYPTOCONDITION) + 405 (vParams push) + 1 (OP_DROP)
        // where vParams inner = 5 (header push) + 34 (pubkey push) + 363 (CNotaryEvidence
        // push with PUSHDATA2 prefix) = 402, and outer push adds 3 (PUSHDATA2 + u16 LE).
        let ne = vec![0u8; 360];
        let mut buf = Vec::new();
        write_eval_notary_evidence_script(&mut buf, &ne);
        assert_eq!(buf.len(), 447);
        assert_eq!(buf[40], OP_CHECKCRYPTOCONDITION);
        assert_eq!(&buf[41..44], &[OP_PUSHDATA2, 0x92, 0x01], "vParams outer push = 402 bytes");
        assert_eq!(buf[buf.len() - 1], OP_DROP);
    }

    #[test]
    fn eval_notary_evidence_script_places_notary_bytes_correctly() {
        // Sanity: given a small distinctive CNotaryEvidence, its bytes end up
        // exactly where the layout predicts.
        let ne = [0xEE; 100];
        let mut buf = Vec::new();
        write_eval_notary_evidence_script(&mut buf, &ne);
        // vParams inner = 5 (header push) + 34 (pubkey push) + 102 (ne push
        // with OP_PUSHDATA1 prefix, since 100 > 76) = 141.
        // Outer push uses OP_PUSHDATA1 (since 141 > 76 and <= 255): 2-byte prefix.
        // vParams total on wire = 2 + 141 = 143. Full = 40 + 1 + 143 + 1 = 185.
        assert_eq!(buf.len(), 185);
        assert_eq!(&buf[41..43], &[OP_PUSHDATA1, 141]);
        // Inside vParams: 5 (header) + 34 (pubkey) + 2 (ne push prefix) = 41
        // → ne bytes at offset 43 + 41 = 84.
        assert_eq!(&buf[84..184], &ne);
    }
}
