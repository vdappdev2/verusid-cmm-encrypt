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
export function encryptDescriptor(input) {
    const plaintextBytes = normalizePlaintext(input.plaintext);
    const outerVdxfKey = normalizeTwentyByte(input.outerVdxfKey, 'outerVdxfKey');
    const systemId = normalizeTwentyByte(input.systemId, 'systemId');
    const signature = input.signature != null ? toUint8Array(input.signature) : null;
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
        dataDepositOutputScripts: result.dataDepositOutputScripts.map((s) => Buffer.from(s)),
        publishedIvk: Buffer.from(result.publishedIvk),
        outerEpk: Buffer.from(result.outerEpk),
        ephemeralDiversifier: Buffer.from(result.ephemeralDiversifier),
        ephemeralPkD: Buffer.from(result.ephemeralPkD),
    };
}
// --- Normalization helpers ------------------------------------------------
function normalizePlaintext(p) {
    if (p === null || p === undefined) {
        throw new Error('plaintext must not be null or undefined');
    }
    if (Buffer.isBuffer(p))
        return new Uint8Array(p);
    if (p instanceof Uint8Array)
        return p;
    if (typeof p === 'string')
        return new TextEncoder().encode(p);
    if (typeof p !== 'object') {
        throw new Error(`plaintext must be a string, Buffer/Uint8Array, or object; got ${typeof p}`);
    }
    // Reject byte-adjacent views (Int8Array, DataView, ArrayBuffer, ...) that
    // would otherwise silently JSON.stringify to '{}' or '{"0":1,...}' instead
    // of being treated as raw bytes. Callers passing binary must use Buffer or
    // Uint8Array explicitly.
    if (ArrayBuffer.isView(p) || p instanceof ArrayBuffer) {
        throw new Error(`plaintext binary input must be a Buffer or Uint8Array; got ${p.constructor.name}`);
    }
    // Reject non-plain objects (Map, Set, Promise, Date, class instances, ...)
    // which JSON.stringify silently reduces to '{}' or an ISO string instead of
    // the caller's expected structure. Only plain `{}` / `Object.create(null)`
    // objects and arrays are accepted.
    const proto = Object.getPrototypeOf(p);
    if (proto !== Object.prototype && proto !== null && !Array.isArray(p)) {
        throw new Error(`plaintext object must be a plain object or array; got ${p.constructor?.name ?? 'unknown'}`);
    }
    return new TextEncoder().encode(JSON.stringify(p));
}
function toUint8Array(b) {
    if (Buffer.isBuffer(b))
        return new Uint8Array(b);
    if (b instanceof Uint8Array)
        return b;
    throw new Error(`signature must be a Buffer or Uint8Array; got ${typeof b}`);
}
/**
 * Accepts 20 bytes as `Buffer`/`Uint8Array` (LE wire order, passthrough) or
 * as a 40-char hex string in BE display form (byte-reversed to LE wire).
 * Any other length or non-hex character throws.
 */
function normalizeTwentyByte(v, name) {
    if (typeof v === 'string') {
        if (!/^[0-9a-fA-F]{40}$/.test(v)) {
            throw new Error(`${name} must be a 40-char hex string or a 20-byte binary; got string of length ${v.length}`);
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
//# sourceMappingURL=index.js.map