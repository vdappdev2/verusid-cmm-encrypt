# verusid-cmm-encrypt

Pure-Rust writer library for Verus identity **content-multimap** entries in the
`flags:13` public-decrypt envelope shape. Counterpart to
[`verusid-cmm-decrypt`](../verusid-cmm-decrypt).

Status: **early implementation**, scope-committed 2026-08-18. The crypto layer
is byte-parity-proven against real daemon-written entries; the framing layer is
under active construction. Not yet suitable for production use.

## What it does

Given a plaintext payload and an outer VDXF key, produce the two byte artifacts
a caller needs to compose a `flags:13` `updateidentity` transaction:

1. The **cmm entry bytes** — the encrypted outer `CVDXFDataDescriptor` to
   insert into `Identity.content_multimap` under the caller's chosen VDXF key.
2. The **data-deposit transaction outputs** — one or more
   `EVAL_NOTARY_EVIDENCE` transparent outputs carrying the second-stage
   ciphertext that the outer descriptor's `CCrossChainDataRef` points at.

The library is bytes-in / bytes-out. It has no dependency on any specific
tx-builder crate and does not sign, submit, or wallet-manage anything. Consumers
compose the two artifacts into a `updateidentity` transaction using whatever
signing stack they already have.

## What it does not do

- Not a wallet. No key storage, no fee estimation, no broadcast.
- Not a tx builder. Consumers wire the outputs into a v4 transaction themselves.
- Not a signer. The ephemeral Sapling spending key generated per write goes out
  of scope with the call — the daemon does the same.
- Not a chunker (yet). Payloads above the single-output chunk threshold
  (~5.8 KB plaintext) are Phase-2 work.

## Byte-parity guarantee

The correctness gate is byte-parity against
[VerusCoin](https://github.com/VerusCoin/VerusCoin) `updateidentity {data:{}}`
envelope writes. Reference at `d1df9b7d254aacbc12070da48640edf84312200b`
(2026-07-31). Every cryptographic primitive is a direct pure-Rust equivalent of
what the daemon calls:

| Daemon | This crate |
|---|---|
| `librustzcash_sapling_ka_agree` | `jubjub` scalar mult |
| `librustzcash_sapling_ka_derivepublic` | `jubjub` scalar mult |
| `KDF_Sapling` (Blake2b-256, `"Zcash_SaplingKDF"` personalization) | `blake2b_simd` |
| `crypto_aead_chacha20poly1305_ietf_encrypt` (zero nonce, no AAD) | `chacha20poly1305::ChaCha20Poly1305` |

Byte-parity for the decrypt direction is proven by
[`byte-parity-experiment`](../chainvue-things/flags13-writer-lib/scoping/byte-parity-experiment/)
against a live `t1@` VRSCTEST entry at height 578528. See the scoping report at
`../chainvue-things/flags13-writer-lib/scoping/scope-report.md` for the go/no-go
analysis.

## License

MIT. See `LICENSE`.
