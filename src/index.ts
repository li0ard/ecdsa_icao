import { createCurve } from "@noble/curves/_shortw_utils";
import { Field } from "@noble/curves/abstract/modular";
import { type CurveFn } from "@noble/curves/abstract/weierstrass";
import { sha1 } from "@noble/hashes/sha1";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha384, sha512 } from "@noble/hashes/sha512";
import type { Hash } from "@noble/hashes/utils";
import { type ECParameters } from "@peculiar/asn1-ecc";
import TLV from "node-tlv";

/**
 * Convert buffer to BigInt
 * @param data Input buffer
 */
const bufToBigInt = (data: Buffer): bigint => {
    return BigInt(`0x${data.toString("hex")}`)
}

/**
 * Parse certificate EC parameters and generate curve object
 * @param params [Public key parameters](https://github.com/PeculiarVentures/asn1-schema/blob/master/packages/ecc/src/ec_parameters.ts)
 */
export const curveFromECParams = (params: ECParameters): CurveFn => {
    if(!params.specifiedCurve) throw new Error("Only explicit ECC parameters supported");
    if(params.specifiedCurve.fieldID.fieldType != "1.2.840.10045.1.1") throw new Error("Only explicit [X9.62] schema supported");

    let base = Buffer.from(params.specifiedCurve.base.buffer).subarray(1)

    return createCurve({
        a: bufToBigInt(Buffer.from(params.specifiedCurve.curve.a)),
        b: bufToBigInt(Buffer.from(params.specifiedCurve.curve.b)),
        Fp: Field(bufToBigInt(TLV.parse(Buffer.from(params.specifiedCurve.fieldID.parameters)).bValue)),
        n: bufToBigInt(Buffer.from(params.specifiedCurve.order)),
        Gx: bufToBigInt(base.subarray(0, base.length/2)),
        Gy: bufToBigInt(base.subarray(base.length/2)),
        h: BigInt(params.specifiedCurve.cofactor as unknown as number),
    } as const, sha512) // random hash, because it is not used here, but it is needed as a parameter
}

export interface HashFn {
    (msg: Uint8Array | string, opts?: any): Uint8Array,
    outputLen: number,
    blockLen: number,
    create(): Hash<any>
}

/**
 * Get hash function by signature algorithm OID
 * @param oid OID of signature algorithm
 */
export const hashFromECDSAOID = (oid: string): HashFn => {
    let algorithms: {[key: string]: HashFn} = {
        "1.2.840.10045.4.1": sha1,
        "1.2.840.10045.4.3.1": sha224,
        "1.2.840.10045.4.3.2": sha256,
        "1.2.840.10045.4.3.3": sha384,
        "1.2.840.10045.4.3.4": sha512,

    }
    return algorithms[oid]
}
