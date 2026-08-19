# verusid-cmm-encrypt

Pure-Rust writer library for Verus identity **content-multimap** entries in the
`flags:13` public-decrypt envelope shape.

Status: feature-complete for the public-decrypt path. 84 unit + 7 fixture
byte-parity tests pass. Every framing layer is anchored against a live
daemon-written entry byte-for-byte; the outer AEAD path is additionally
verified end-to-end against a running daemon via `decryptdata`. Chunking
(payloads larger than a single tx output can hold) and `signdata`
SignatureDataKey attachment are both supported and daemon-verified.

WebAssembly bindings live in [`wasm/`](wasm) and expose the same API to
JavaScript.

## What it does

Given a plaintext payload, an outer VDXF key, and (optionally) a caller-
supplied signature, produce the byte artifacts a caller needs to compose a
`flags:13` `updateidentity` transaction:

1. The **cmm entry bytes** — one encrypted outer `CVDXFDataDescriptor` to
   insert into `Identity.content_multimap` under the caller's chosen VDXF
   key. When a signature is attached, the entry is a second descriptor
   appended to the first: `sub_object = 1`, `label = "signature"`,
   `mime = "application/json"` (matches `pbaasrpc.cpp:16380-16394`).
2. The **data-deposit transaction outputs** — one `EVAL_NOTARY_EVIDENCE`
   transparent output per chunk. Payloads that fit in a single output
   (~5.7 KB effective ceiling) produce one output; larger payloads auto-chunk
   via a byte-exact port of `CNotaryEvidence::BreakApart`
   (`block.cpp:817-842`). All outputs have `nValue = 0`.

The library is bytes-in / bytes-out. It has no dependency on any specific
tx-builder crate and does not sign, submit, or wallet-manage anything.
Consumers compose the returned artifacts into an `updateidentity` transaction
using whatever signing stack they already have.

## What it does not do

- Not a wallet. No key storage, no fee estimation, no broadcast.
- Not a tx builder. Consumers wire the outputs into a v4 transaction themselves.
- Not a Sapling-address encryption path. Only the `flags:13` public-decrypt
  shape is supported — the ivk is published in-band so anyone reading the
  chain can decrypt.
- Does not produce signatures. Callers assemble signature bytes externally
  (e.g., via the daemon's `signdata` RPC or an offline `CVDXFSignatureData`
  composition) and pass them in via the `signature` field.

## Byte-parity guarantee

The correctness gate is byte-parity against
[VerusCoin](https://github.com/VerusCoin/VerusCoin) `updateidentity {data:{}}`
envelope writes. Reference at commit
`d1df9b7d254aacbc12070da48640edf84312200b` (2026-07-31). Every cryptographic
primitive is a direct pure-Rust equivalent of what the daemon calls:

| Daemon | This crate |
|---|---|
| `librustzcash_sapling_ka_agree` | `jubjub` scalar mult |
| `librustzcash_sapling_ka_derivepublic` | `jubjub` scalar mult |
| `KDF_Sapling` (Blake2b-256, `"Zcash_SaplingKDF"` personalization) | `blake2b_simd` |
| `crypto_aead_chacha20poly1305_ietf_encrypt` (zero nonce, no AAD) | `chacha20poly1305::ChaCha20Poly1305` |

Byte-parity is proven by seven anchor tests in `tests/stage1_decrypt.rs` that
extract the corresponding bytes from a live VRSCTEST envelope entry at height
578528 (fixture at `tests/fixtures/t1_578528.json`) and reserialize them via
our writer, asserting byte-exact equality at every framing layer.

## Daemon round-trip verification

The outer AEAD half is additionally validated against a running daemon. Two
examples emit the exact `datadescriptor` JSON that VerusCoin's `decryptdata`
RPC accepts:

```
cargo run --example emit_datadescriptor_json           # data-only round-trip
cargo run --example emit_signed_datadescriptors_json   # data + signature round-trip
```

Then feed each block to a running daemon:

```
verus -chain=VRSCTEST decryptdata '<pasted JSON>'
```

A daemon that shares librustzcash's Sapling primitives returns a CCDR pointer
with `output.voutnum` matching the requested `data_deposit_vout_index`, self-
ref `output.txid` (envelope writes always self-refer), and `subobject = 0`
for the data descriptor / `subobject = 1` for the signature descriptor. No
wallet or on-chain state required — the outer decrypt path is stateless for
the public-decrypt shape.

## License

MIT. See `LICENSE`.
