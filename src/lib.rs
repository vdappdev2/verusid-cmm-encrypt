//! Pure-Rust writer for Verus flags:13 public-decrypt cmm entries.
//!
//! See `README.md` for scope and usage. Byte-parity target is the
//! `updateidentity {data:{}}` envelope handler in VerusCoin
//! `src/rpc/pbaasrpc.cpp:16042-16424` at commit
//! `d1df9b7d254aacbc12070da48640edf84312200b` (2026-07-31).

pub mod cc_script;
pub mod crypto;
pub mod data_descriptor;
pub mod data_ref;
pub mod ephemeral;
pub mod notary_evidence;
pub mod vdxf;
pub mod wire;
