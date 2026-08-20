# verusid-cmm-encrypt

Write Verus identity **content-multimap** entries in the `flags:13`
public-decrypt envelope shape from TypeScript / JavaScript. TS wrapper +
WASM-Sapling AEAD over a pure-Rust core; produces bytes-in / bytes-out that a
caller composes into an `updateidentity` transaction.

Byte-parity anchored against the daemon's write path
([VerusCoin `pbaasrpc.cpp:16042-16424`](https://github.com/VerusCoin/VerusCoin/blob/master/src/rpc/pbaasrpc.cpp))
and cross-checked against a live daemon via `decryptdata`. Feature-complete for
the public-decrypt path: chunking (`CNotaryEvidence::BreakApart`), signdata
`SignatureDataKey` attachment, and payloads of arbitrary size.

## Installation

Pin to a specific commit SHA, matching the sibling
[`verusid-cmm-decrypt`](https://github.com/vdappdev2/verusid-cmm-decrypt)
package:

```json
{
  "dependencies": {
    "verusid-cmm-encrypt": "git+https://github.com/vdappdev2/verusid-cmm-encrypt.git#<commit-sha>"
  }
}
```

Node.js ≥ 20. No Rust toolchain required — the WASM artifact is checked into
`dist/` so `yarn add` / `npm install` gives you a ready-to-import package.

## Usage

```typescript
import { encryptDescriptor } from 'verusid-cmm-encrypt';

const result = encryptDescriptor({
  plaintext: { message: 'hello world', ts: Date.now() },
  outerVdxfKey: 'a4ad4638eb96fb16c1a7d3e3cea86bcb7a243ace112286e1f4a64481a34c4100',
  systemId: 'a6ef9ea235635e328124ff3429db9f9e91b64e2d',
  label: 'user_profile',
  dataDepositVoutIndex: 0,
});

// result.cmmEntry: { vdxfKey: Buffer, value: Buffer }
//   → push into Identity.content_multimap
// result.dataDepositOutputScripts: Buffer[]
//   → add each as an EVAL_NOTARY_EVIDENCE transparent output (nValue = 0),
//     contiguously, starting at dataDepositVoutIndex
// result.publishedIvk: Buffer
//   → the 32-byte ivk published on-chain; anyone with it can decrypt
```

Full input shape:

```typescript
type EncryptDescriptorInput = {
  plaintext: string | Uint8Array | Buffer | object;
  // 20-byte binary (LE wire) OR 40-char hex (BE display, from getvdxfid)
  outerVdxfKey: Buffer | Uint8Array | string;
  // 20-byte binary (LE wire) OR 40-char hex (BE display, from getcurrency)
  systemId: Buffer | Uint8Array | string;
  label?: string | null;                   // ≤ 64 UTF-8 bytes, optional
  mimeType?: string | null;                // ≤ 128 bytes, optional
  dataDepositVoutIndex: number;            // u32
  signature?: Buffer | Uint8Array | null;  // optional attached signature
};
```

Full output shape:

```typescript
type EncryptDescriptorOutput = {
  cmmEntry: { vdxfKey: Buffer; value: Buffer };
  dataDepositOutputScripts: Buffer[];  // 1 normally, N when chunking triggers
  publishedIvk: Buffer;
  outerEpk: Buffer;
  ephemeralDiversifier: Buffer;
  ephemeralPkD: Buffer;
};
```

### Chunking

Payloads that produce an `EVAL_NOTARY_EVIDENCE` script larger than 6000 bytes
(≈ 5.7 KB plaintext, after envelope overhead) are transparently split across
multiple tx outputs via a byte-exact port of `CNotaryEvidence::BreakApart`
(`block.cpp:817-842`). `dataDepositOutputScripts.length` reflects the chunk
count; add all outputs contiguously starting at `dataDepositVoutIndex`. The
daemon reader walks MULTIPART outputs and reassembles on retrieval.

### Signature attachment

When you pass `signature`, the encrypt path emits a second
`CVDXFDataDescriptor` appended to the cmm entry value with
`sub_object = 1`, `label = "signature"`, `mime = "application/json"` (matches
the daemon's `signdata` output at `pbaasrpc.cpp:16380-16394`). Both
descriptors are encrypted to the same published IVK — one key decrypts both.

Producing the signature bytes themselves is out of scope. Typical sources:
the daemon's `signdata` RPC, or an offline `CVDXFSignatureData` composition.

## What it does not do

- Not a wallet. No key storage, no fee estimation, no broadcast.
- Not a tx builder. Consumers wire the outputs into a v4 transaction themselves.
- Not a Sapling-address encryption path. Only `flags:13` public-decrypt with
  in-band ivk.
- Does not produce signatures. Callers assemble signatures externally.

## Rust API

The pure-Rust crate at [`rust/`](rust) is also usable directly, without the
TypeScript wrapper or WASM. See [`rust/README.md`](rust/README.md) for the
Rust-focused documentation, including byte-parity guarantees, the daemon
round-trip verification examples, and the layered API.

## Testing

TypeScript wrapper (private tests, run locally):

```
yarn build:wasm && yarn build
node --test test/*.test.mjs
```

Rust crate:

```
yarn test:rust           # or: cd rust && cargo test
```

## License

MIT. See [`LICENSE`](LICENSE).
