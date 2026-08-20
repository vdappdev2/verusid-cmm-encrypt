/* tslint:disable */
/* eslint-disable */

export interface EncryptPublicDecryptRequest {
    plaintext: Uint8Array;
    outerVdxfKey: Uint8Array;
    systemId: Uint8Array;
    label?: string | null;
    mimeType?: string | null;
    dataDepositVoutIndex: number;
    signature?: Uint8Array | null;
}

export interface CmmEntry {
    vdxfKey: Uint8Array;
    value: Uint8Array;
}

export interface EncryptPublicDecryptResult {
    cmmEntry: CmmEntry;
    dataDepositOutputScripts: Uint8Array[];
    publishedIvk: Uint8Array;
    outerEpk: Uint8Array;
    ephemeralDiversifier: Uint8Array;
    ephemeralPkD: Uint8Array;
}



/**
 * Encrypt `request.plaintext` into a `flags:13` public-decrypt cmm entry and
 * its accompanying `EVAL_NOTARY_EVIDENCE` data-deposit output(s).
 *
 * See the module-level docs for the JS request/response shape. Errors surface
 * as JavaScript `Error` instances with a message identifying the failing
 * input field or composed layer.
 */
export function encryptPublicDecrypt(request: EncryptPublicDecryptRequest): EncryptPublicDecryptResult;
