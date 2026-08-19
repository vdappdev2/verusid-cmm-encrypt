// Node smoke test for verusid-cmm-encrypt-wasm.
//
// Usage:
//   cd wasm && wasm-pack build --target nodejs --out-dir tests/node/pkg
//   node wasm/tests/node/smoke.mjs
//
// Asserts the binding is wired end-to-end: input types accepted, output shape
// matches the documented layout, RNG is live (two calls with identical input
// produce different ephemeral material).

import assert from "node:assert/strict";
import { encryptPublicDecrypt } from "./pkg/verusid_cmm_encrypt_wasm.js";

const plaintext = new TextEncoder().encode("hello from node smoke test");
const outerVdxfKey = new Uint8Array(20).fill(0xaa);
const systemId = new Uint8Array(20).fill(0xbb);

const first = encryptPublicDecrypt(
  plaintext,
  outerVdxfKey,
  systemId,
  null,
  null,
  0,
);

// --- Shape checks ---
assert.ok(first.cmmEntry, "result.cmmEntry present");
assert.ok(first.cmmEntry.vdxfKey instanceof Uint8Array, "vdxfKey is Uint8Array");
assert.ok(first.cmmEntry.value instanceof Uint8Array, "value is Uint8Array");
assert.ok(first.dataDepositOutputScript instanceof Uint8Array);
assert.ok(first.publishedIvk instanceof Uint8Array);
assert.ok(first.outerEpk instanceof Uint8Array);
assert.ok(first.ephemeralDiversifier instanceof Uint8Array);
assert.ok(first.ephemeralPkD instanceof Uint8Array);

assert.equal(first.cmmEntry.vdxfKey.length, 20, "vdxfKey length");
assert.equal(first.publishedIvk.length, 32, "ivk length");
assert.equal(first.outerEpk.length, 32, "epk length");
assert.equal(first.ephemeralDiversifier.length, 11, "diversifier length");
assert.equal(first.ephemeralPkD.length, 32, "pk_d length");

// --- Byte-layout checks (proven by rlib fixture tests; asserted here again
//     to catch a broken binding boundary that mangles Uint8Array bytes) ---

// outer CDataDescriptor: 0x01 (VARINT version=1) | 0x0D (VARINT flags=13)
assert.equal(first.cmmEntry.value[0], 0x01, "cmm entry byte 0 = version");
assert.equal(first.cmmEntry.value[1], 0x0d, "cmm entry byte 1 = flags:13");

// data-deposit script: first byte is master push length 0x27 (39 bytes)
assert.equal(
  first.dataDepositOutputScript[0],
  0x27,
  "data-deposit script byte 0 = 0x27 master push",
);

// vdxfKey field echoes the caller's input verbatim
assert.deepEqual(
  Array.from(first.cmmEntry.vdxfKey),
  Array.from(outerVdxfKey),
  "cmm entry vdxfKey mirrors input",
);

// --- RNG liveness: same input, different randomness → different ephemerals ---
const second = encryptPublicDecrypt(
  plaintext,
  outerVdxfKey,
  systemId,
  null,
  null,
  0,
);
assert.notDeepEqual(
  Array.from(first.publishedIvk),
  Array.from(second.publishedIvk),
  "two calls with identical input produce different published_ivk (RNG live)",
);

// --- Error path: wrong-length key rejected with a JS Error ---
assert.throws(
  () =>
    encryptPublicDecrypt(
      plaintext,
      new Uint8Array(19),
      systemId,
      null,
      null,
      0,
    ),
  /outerVdxfKey must be exactly 20 bytes/,
  "19-byte outerVdxfKey rejected",
);

console.log("smoke.mjs: OK");
