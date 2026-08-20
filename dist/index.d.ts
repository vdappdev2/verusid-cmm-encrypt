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
export declare function encryptDescriptor(input: EncryptDescriptorInput): EncryptDescriptorOutput;
//# sourceMappingURL=index.d.ts.map