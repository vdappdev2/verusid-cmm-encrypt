// Node smoke test for verusid-cmm-encrypt-wasm.
//
// Usage:
//   cd wasm && wasm-pack build --target nodejs --out-dir tests/node/pkg
//   node wasm/tests/node/smoke.mjs
//
// Asserts the binding is wired end-to-end: options-object request accepted,
// output shape matches the documented layout, RNG is live (two calls with
// identical input produce different ephemeral material), chunking triggers
// above threshold, and signature attachment appends a second descriptor.

import assert from "node:assert/strict";
import { encryptPublicDecrypt } from "./pkg/verusid_cmm_encrypt_wasm.js";

const plaintext = new TextEncoder().encode("hello from node smoke test");
const outerVdxfKey = new Uint8Array(20).fill(0xaa);
const systemId = new Uint8Array(20).fill(0xbb);

const first = encryptPublicDecrypt({
  plaintext,
  outerVdxfKey,
  systemId,
  label: null,
  mimeType: null,
  dataDepositVoutIndex: 0,
  signature: null,
});

// --- Shape checks ---
assert.ok(first.cmmEntry, "result.cmmEntry present");
assert.ok(first.cmmEntry.vdxfKey instanceof Uint8Array, "vdxfKey is Uint8Array");
assert.ok(first.cmmEntry.value instanceof Uint8Array, "value is Uint8Array");
assert.ok(Array.isArray(first.dataDepositOutputScripts), "scripts is Array");
assert.equal(first.dataDepositOutputScripts.length, 1, "small payload = 1 script");
assert.ok(first.dataDepositOutputScripts[0] instanceof Uint8Array);
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
  first.dataDepositOutputScripts[0][0],
  0x27,
  "data-deposit script byte 0 = 0x27 master push",
);

// vdxfKey field echoes the caller's input verbatim
assert.deepEqual(
  Array.from(first.cmmEntry.vdxfKey),
  Array.from(outerVdxfKey),
  "cmm entry vdxfKey mirrors input",
);

// --- Optional fields absent: omitting label/mimeType/signature works ---
const withoutOptionals = encryptPublicDecrypt({
  plaintext,
  outerVdxfKey,
  systemId,
  dataDepositVoutIndex: 0,
});
assert.equal(
  withoutOptionals.cmmEntry.value[1],
  0x0d,
  "call succeeds with only required fields",
);

// --- RNG liveness: same input, different randomness → different ephemerals ---
const second = encryptPublicDecrypt({
  plaintext,
  outerVdxfKey,
  systemId,
  label: null,
  mimeType: null,
  dataDepositVoutIndex: 0,
  signature: null,
});
assert.notDeepEqual(
  Array.from(first.publishedIvk),
  Array.from(second.publishedIvk),
  "two calls with identical input produce different published_ivk (RNG live)",
);

// --- Chunking: payload above ~5.7 KB threshold produces multiple scripts ---
const bigPayload = new Uint8Array(10_000).fill(0x5a);
const chunked = encryptPublicDecrypt({
  plaintext: bigPayload,
  outerVdxfKey,
  systemId,
  label: null,
  mimeType: null,
  dataDepositVoutIndex: 0,
  signature: null,
});
assert.ok(
  chunked.dataDepositOutputScripts.length >= 2,
  `10 KB payload must produce >=2 scripts (got ${chunked.dataDepositOutputScripts.length})`,
);
for (const script of chunked.dataDepositOutputScripts) {
  assert.ok(script instanceof Uint8Array);
  assert.ok(
    script.length < 6000,
    `each chunk script must fit under MAX_SCRIPT_ELEMENT_SIZE (got ${script.length})`,
  );
}

// --- Signature attachment: passing a signature appends a second descriptor
//     to the cmm entry value ---
const sigBytes = new TextEncoder().encode("caller-supplied signature blob");
const signed = encryptPublicDecrypt({
  plaintext,
  outerVdxfKey,
  systemId,
  label: null,
  mimeType: null,
  dataDepositVoutIndex: 0,
  signature: sigBytes,
});
assert.ok(
  signed.cmmEntry.value.length > first.cmmEntry.value.length,
  "signed cmm value must be larger than unsigned",
);
// Signature descriptor sits after the first descriptor. Parse the first
// descriptor's length: 3 (v+flags+CS) + ct_len + 33 (epk) + 33 (ivk).
const ctLen = signed.cmmEntry.value[2];
const firstDescEnd = 3 + ctLen + 33 + 33;
assert.equal(
  signed.cmmEntry.value[firstDescEnd],
  0x01,
  "second descriptor version byte",
);
assert.equal(
  signed.cmmEntry.value[firstDescEnd + 1],
  0x0d,
  "second descriptor flags = 13",
);

// --- Error paths ---

// Wrong-length outerVdxfKey rejected.
assert.throws(
  () =>
    encryptPublicDecrypt({
      plaintext,
      outerVdxfKey: new Uint8Array(19),
      systemId,
      dataDepositVoutIndex: 0,
    }),
  /outerVdxfKey must be exactly 20 bytes/,
  "19-byte outerVdxfKey rejected",
);

// Missing required field rejected.
assert.throws(
  () =>
    encryptPublicDecrypt({
      plaintext,
      outerVdxfKey,
      // systemId omitted
      dataDepositVoutIndex: 0,
    }),
  /systemId is required/,
  "missing systemId rejected",
);

// Wrong type on a required field rejected.
assert.throws(
  () =>
    encryptPublicDecrypt({
      plaintext,
      outerVdxfKey,
      systemId,
      dataDepositVoutIndex: -1,
    }),
  /dataDepositVoutIndex must be a non-negative integer/,
  "negative dataDepositVoutIndex rejected",
);

console.log("smoke.mjs: OK");
