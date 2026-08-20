# verusid-cmm-encrypt-wasm

WebAssembly bindings for [`verusid-cmm-encrypt`](..), the pure-Rust writer for
Verus identity content-multimap entries in the `flags:13` public-decrypt
envelope shape.

Bytes-in / bytes-out. No wallet, no tx builder, no RPC. Callers compose the
returned `cmmEntry` and `dataDepositOutputScripts` into an `updateidentity`
transaction using whatever signing stack they already have.

## Build

```
cd wasm
wasm-pack build --target nodejs   # or --target web / --target bundler
```

Produces a JS/TS package under `pkg/` (or `--out-dir` if overridden). The
TypeScript wrapper at the repo root builds into `../src/wasm/` via
`yarn build:wasm`.

## JS usage

```js
import { encryptPublicDecrypt } from "verusid-cmm-encrypt-wasm";

const result = encryptPublicDecrypt({
  plaintext,             // Uint8Array
  outerVdxfKey,          // Uint8Array, exactly 20 bytes (LE from getvdxfid)
  systemId,              // Uint8Array, exactly 20 bytes (LE ASSETCHAINS_CHAINID)
  label,                 // string | null (optional)
  mimeType,              // string | null (optional)
  dataDepositVoutIndex,  // number, u32 — index the first deposit output occupies
  signature,             // Uint8Array | null (optional) — caller-supplied
                         //   signature attached as a second cmm descriptor
});

// {
//   cmmEntry: { vdxfKey: Uint8Array, value: Uint8Array },
//   dataDepositOutputScripts: Uint8Array[],   // 1 element normally; N when
//                                             // payload triggers BreakApart
//                                             // chunking
//   publishedIvk: Uint8Array,                 // one key decrypts data AND
//                                             // signature descriptors
//   outerEpk: Uint8Array,
//   ephemeralDiversifier: Uint8Array,
//   ephemeralPkD: Uint8Array,
// }
```

TypeScript users import the request and result interfaces directly:

```ts
import {
  encryptPublicDecrypt,
  type EncryptPublicDecryptRequest,
  type EncryptPublicDecryptResult,
} from "verusid-cmm-encrypt-wasm";
```

Each element of `dataDepositOutputScripts` is a full `scriptPubKey` for an
`EVAL_NOTARY_EVIDENCE` transparent output with `nValue = 0`. Add them
contiguously to the transaction starting at `dataDepositVoutIndex`; the
daemon reader walks contiguous MULTIPART outputs to reassemble chunked
payloads.

## Randomness

`OsRng` is constructed inside the binding. On `wasm32-unknown-unknown`
`getrandom`'s `js` feature routes it through the Web Crypto API (browser) or
`node:crypto` (Node). Callers do not source entropy.

## Testing

Rust host build (`cargo build`) compiles the `rlib` half; behavior of the
compiled Wasm module is verified from JavaScript through the TypeScript
wrapper's Node test suite at the repo root.

```
yarn build:wasm && yarn build
node --test test/*.test.mjs
```

The wrapper suite covers wasm boot (produces the documented `flags:13` byte
layout — `0x01 0x0D` header, `0x27` master push on the deposit script), RNG
liveness (two calls with identical input diverge), chunking (a 10 KB payload
produces multiple sub-6000-byte scripts), and signature attachment (the
signed cmm value is larger than the unsigned one and its second descriptor
starts with the flags:13 header at the correct offset).

## Byte-parity

Every cryptographic and framing byte this binding emits is produced by the
parent crate, which is byte-parity-anchored against a real daemon-written
`flags:13` entry (`t1@` VRSCTEST, height 578528). See [`../rust/README.md`](../rust/README.md)
and [`../rust/tests/stage1_decrypt.rs`](../rust/tests/stage1_decrypt.rs) for the fixture
tests.

## License

MIT. See [`../LICENSE`](../LICENSE).
