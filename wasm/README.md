# verusid-cmm-encrypt-wasm

WebAssembly bindings for [`verusid-cmm-encrypt`](..), the pure-Rust writer for
Verus identity content-multimap entries in the `flags:13` public-decrypt
envelope shape.

Bytes-in / bytes-out. No wallet, no tx builder, no RPC. Callers compose the
returned `cmmEntry` and `dataDepositOutputScript` into an `updateidentity`
transaction using whatever signing stack they already have.

## Build

```
cd wasm
wasm-pack build --target nodejs   # or --target web / --target bundler
```

Produces a JS/TS package under `pkg/` (or `--out-dir` if overridden). The
default `--out-dir` is `pkg/`; the smoke test builds into `tests/node/pkg/`.

## JS usage

```js
import { encryptPublicDecrypt } from "verusid-cmm-encrypt-wasm";

const result = encryptPublicDecrypt(
  plaintextBytes,       // Uint8Array
  outerVdxfKey,         // Uint8Array, exactly 20 bytes (LE from getvdxfid)
  systemId,             // Uint8Array, exactly 20 bytes (LE ASSETCHAINS_CHAINID)
  label,                // string | null
  mimeType,             // string | null
  dataDepositVoutIndex, // number, u32 — index the deposit output will occupy
);

// {
//   cmmEntry: { vdxfKey: Uint8Array, value: Uint8Array },
//   dataDepositOutputScript: Uint8Array,   // full scriptPubKey, value=0 output
//   publishedIvk: Uint8Array,              // anyone holding this can decrypt
//   outerEpk: Uint8Array,
//   ephemeralDiversifier: Uint8Array,
//   ephemeralPkD: Uint8Array,
// }
```

## Randomness

`OsRng` is constructed inside the binding. On `wasm32-unknown-unknown`
`getrandom`'s `js` feature routes it through the Web Crypto API (browser) or
`node:crypto` (Node). Callers do not source entropy.

## Testing

Rust host build (`cargo build`) compiles the `rlib` half; behavior of the
compiled Wasm module is verified from JavaScript.

```
cd wasm
wasm-pack build --target nodejs --out-dir tests/node/pkg
node tests/node/smoke.mjs
```

The smoke test checks output shape, the documented `flags:13` byte layout
(`0x01 0x0D` header, `0x27` master push on the deposit script), and that two
calls with identical input diverge — proving the RNG is live inside the module.

## Byte-parity

Every cryptographic and framing byte this binding emits is produced by the
parent crate, which is byte-parity-anchored against a real daemon-written
`flags:13` entry (`t1@` VRSCTEST, height 578528). See [`../README.md`](../README.md)
and [`../tests/stage1_decrypt.rs`](../tests/stage1_decrypt.rs) for the fixture
tests.

## License

MIT. See [`../LICENSE`](../LICENSE).
