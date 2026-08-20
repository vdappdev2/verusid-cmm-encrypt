/**
 * High-level TypeScript wrapper around the WASM-Sapling encrypt core.
 *
 *   encryptDescriptor(input) -> { cmmEntry, dataDepositOutputScripts, ... }
 *
 * Produces the two byte artifacts a caller needs to compose a `flags:13`
 * public-decrypt `updateidentity` transaction:
 *
 *   - `cmmEntry`: the encrypted outer `CVDXFDataDescriptor` (or two of them,
 *     concatenated, when a signature is attached) to insert into the
 *     identity's `contentmultimap` under the caller's chosen VDXF key.
 *   - `dataDepositOutputScripts`: one full `scriptPubKey` per
 *     `EVAL_NOTARY_EVIDENCE` transparent output (all `nValue = 0`); length 1
 *     for small payloads, N when the payload triggers `BreakApart` chunking.
 *
 * The wrapper is bytes-in / bytes-out. It has no dependency on any specific
 * tx-builder crate and does not sign, submit, or wallet-manage anything.
 * Callers compose the returned artifacts into an `updateidentity` transaction
 * using whatever signing stack they already have.
 *
 * Convenience over the raw WASM binding: accepts hex strings alongside
 * `Buffer`/`Uint8Array` for the binary fields (20-byte VDXF-key and system-ID
 * inputs come from `getvdxfid` / `getcurrency` as big-endian display hex,
 * which this wrapper byte-reverses to the LE wire order the WASM core
 * expects), and accepts `string` / `object` plaintext (auto-encoded as UTF-8
 * / JSON) in addition to raw bytes.
 */

import { encryptPublicDecrypt } from './wasm/verusid_cmm_encrypt.js';

/** Input to [[encryptDescriptor]]. See individual field docs. */
export type EncryptDescriptorInput = {
  /**
   * Payload to encrypt. `string` is encoded as UTF-8, `object` as
   * `JSON.stringify` then UTF-8, `Buffer`/`Uint8Array` passthrough.
   */
  plaintext: string | Uint8Array | Buffer | object;

  /**
   * VDXF key under which this entry will be stored in the identity's cmm.
   * Accepts EITHER a 20-byte `Buffer`/`Uint8Array` (already in little-endian
   * wire order) OR a 40-char hex string in big-endian display form (as
   * returned by `getvdxfid <uri>`).
   */
  outerVdxfKey: Buffer | Uint8Array | string;

  /**
   * Target chain's `ASSETCHAINS_CHAINID`. Same accepted forms as
   * `outerVdxfKey`: 20-byte binary (LE wire order) or 40-char hex (BE
   * display, as returned by `getcurrency`).
   */
  systemId: Buffer | Uint8Array | string;

  /**
   * Optional per-entry label. Embedded inside the encrypted payload (visible
   * only after decrypt). Max 64 UTF-8 bytes; longer values raise a
   * `LimitedStringTooLong` error from the WASM core.
   */
  label?: string | null;

  /**
   * Optional MIME type. Same visibility as `label`. Max 128 bytes.
   */
  mimeType?: string | null;

  /**
   * Vout index the first `EVAL_NOTARY_EVIDENCE` data-deposit output will
   * occupy in the finished transaction. Chunked payloads occupy contiguous
   * outputs starting here.
   */
  dataDepositVoutIndex: number;

  /**
   * Optional caller-supplied signature bytes to attach as a second cmm
   * descriptor (`sub_object = 1`, `label = "signature"`,
   * `mime = "application/json"`; matches the daemon's `signdata` output at
   * `pbaasrpc.cpp:16380-16394`). Both descriptors decrypt with the same
   * published IVK.
   *
   * Producing the signature bytes themselves is out of scope; typical
   * sources are the daemon's `signdata` RPC or an offline
   * `CVDXFSignatureData` composition.
   */
  signature?: Buffer | Uint8Array | null;
};

/** `(vdxf_key, value_bytes)` pair the caller pushes into `content_multimap`. */
export type CmmEntry = {
  vdxfKey: Buffer;
  value: Buffer;
};

/** Output of [[encryptDescriptor]]. */
export type EncryptDescriptorOutput = {
  /** cmm entry to insert into `Identity.content_multimap`. */
  cmmEntry: CmmEntry;
  /**
   * One full `scriptPubKey` per `EVAL_NOTARY_EVIDENCE` transparent output the
   * caller must add. Length 1 for payloads that fit in a single output; N
   * when chunking triggers. Outputs must appear contiguously starting at
   * `input.dataDepositVoutIndex` and all carry `nValue = 0`.
   */
  dataDepositOutputScripts: Buffer[];
  /**
   * The IVK published on-chain in the outer descriptor. Anyone holding it
   * can decrypt both the data descriptor and (when present) the signature
   * descriptor.
   */
  publishedIvk: Buffer;
  /**
   * The outer data descriptor's `epk` field. Together with `publishedIvk`,
   * decrypts the outer ciphertext to the wrapped CCDR pointer.
   */
  outerEpk: Buffer;
  /**
   * Diversifier bytes of the ephemeral Sapling address. Not required for
   * decryption; exposed for reproducibility / logging.
   */
  ephemeralDiversifier: Buffer;
  /**
   * Diversified transmission key of the ephemeral Sapling address. Not
   * required for decryption; exposed for reproducibility / logging.
   */
  ephemeralPkD: Buffer;
};

/**
 * Encrypt a payload into a `flags:13` public-decrypt cmm entry and its
 * accompanying data-deposit output(s). See [[EncryptDescriptorInput]] and
 * [[EncryptDescriptorOutput]] for the full input / output shape.
 *
 * Errors thrown as `Error` instances:
 *   - Input validation failures (wrong-length hex, unknown types, oversized
 *     label / mime) raise before the WASM boundary with a message naming the
 *     offending field.
 *   - Cryptographic layer failures raise from the WASM core with an
 *     `EncryptError` variant prefix (`Wire`, `Crypto`, `Ephemeral`,
 *     `DiversifierSearchExhausted`).
 */
export function encryptDescriptor(
  input: EncryptDescriptorInput,
): EncryptDescriptorOutput {
  const plaintextBytes = normalizePlaintext(input.plaintext);
  const outerVdxfKey = normalizeTwentyByte(input.outerVdxfKey, 'outerVdxfKey');
  const systemId = normalizeTwentyByte(input.systemId, 'systemId');
  const signature =
    input.signature != null ? toUint8Array(input.signature) : null;

  const result = encryptPublicDecrypt({
    plaintext: plaintextBytes,
    outerVdxfKey,
    systemId,
    label: input.label ?? null,
    mimeType: input.mimeType ?? null,
    dataDepositVoutIndex: input.dataDepositVoutIndex,
    signature,
  });

  return {
    cmmEntry: {
      vdxfKey: Buffer.from(result.cmmEntry.vdxfKey),
      value: Buffer.from(result.cmmEntry.value),
    },
    dataDepositOutputScripts: result.dataDepositOutputScripts.map((s) =>
      Buffer.from(s),
    ),
    publishedIvk: Buffer.from(result.publishedIvk),
    outerEpk: Buffer.from(result.outerEpk),
    ephemeralDiversifier: Buffer.from(result.ephemeralDiversifier),
    ephemeralPkD: Buffer.from(result.ephemeralPkD),
  };
}

// --- Normalization helpers ------------------------------------------------

function normalizePlaintext(
  p: string | Uint8Array | Buffer | object,
): Uint8Array {
  if (p === null || p === undefined) {
    throw new Error('plaintext must not be null or undefined');
  }
  if (Buffer.isBuffer(p)) return new Uint8Array(p);
  if (p instanceof Uint8Array) return p;
  if (typeof p === 'string') return new TextEncoder().encode(p);
  return new TextEncoder().encode(JSON.stringify(p));
}

function toUint8Array(b: Buffer | Uint8Array): Uint8Array {
  if (Buffer.isBuffer(b)) return new Uint8Array(b);
  if (b instanceof Uint8Array) return b;
  throw new Error(
    `signature must be a Buffer or Uint8Array; got ${typeof b}`,
  );
}

/**
 * Accepts 20 bytes as `Buffer`/`Uint8Array` (LE wire order, passthrough) or
 * as a 40-char hex string in BE display form (byte-reversed to LE wire).
 * Any other length or non-hex character throws.
 */
function normalizeTwentyByte(
  v: Buffer | Uint8Array | string,
  name: string,
): Uint8Array {
  if (typeof v === 'string') {
    if (!/^[0-9a-fA-F]{40}$/.test(v)) {
      throw new Error(
        `${name} must be a 40-char hex string or a 20-byte binary; got string of length ${v.length}`,
      );
    }
    // Verus displays IDs in BE (network / display order). The WASM core
    // expects LE wire order. Reverse per Bitcoin/Verus convention.
    const be = Buffer.from(v, 'hex');
    const le = Uint8Array.from(be);
    le.reverse();
    return le;
  }
  const arr = Buffer.isBuffer(v) ? new Uint8Array(v) : v;
  if (arr.length !== 20) {
    throw new Error(`${name} must be exactly 20 bytes; got ${arr.length}`);
  }
  return arr;
}
