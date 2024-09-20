import { createCurve } from "@noble/curves/_shortw_utils";
import { Field } from "@noble/curves/abstract/modular";
import { sha1 } from "@noble/hashes/sha1";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha384, sha512 } from "@noble/hashes/sha512";
import { ECParameters } from "@peculiar/asn1-ecc";
import TLV from "node-tlv";

import { p256 } from "@noble/curves/p256"
import { p384 } from "@noble/curves/p384"
import { p521 } from "@noble/curves/p521"
import { secp256k1 } from "@noble/curves/secp256k1"
import { ed25519 } from "@noble/curves/ed25519"
import { ed448 } from "@noble/curves/ed448"

/**
 * Identify curve by `p` field
 * @param params Public key parameters
 */
export const identifyCurveByP = (params: ECParameters) => {
    let curves = [p256, p384, p521, secp256k1, ed25519, ed448]
    let curvesObj: {[key: string]: any} = {}

    for(let i of curves) {
        curvesObj[i.CURVE.p.toString()] = i
    }
    return curvesObj[BigInt(`0x${TLV.parse(Buffer.from(params.specifiedCurve?.fieldID.parameters as ArrayBuffer)).value}`).toString()]
}


/**
 * Convert buffer to BigInt
 * @param data Input buffer
 */
const bufToBigInt = (data: Buffer) => {
    return BigInt(`0x${data.toString("hex")}`)
}

/**
 * Parse certificate EC parameters and generate curve object
 * @param params Public key parameters
 * @param lowS Low order
 */
export const curveFromECParams = (params: ECParameters, lowS: boolean = false) => {
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
        lowS: lowS
    } as const, sha512) // random hash, because it is not used here, but it is needed as a parameter
}

/**
 * Get hash function by signature algorithm OID
 * @param oid OID of signature algorithm
 */
export const hashFromECDSAOID = (oid: string): typeof sha1 | typeof sha256 | typeof sha512 => {
    let algorithms: {[key: string]: typeof sha1 | typeof sha256 | typeof sha512} = {
        "1.2.840.10045.4.1": sha1,
        "1.2.840.10045.4.3.1": sha224,
        "1.2.840.10045.4.3.2": sha256,
        "1.2.840.10045.4.3.3": sha384,
        "1.2.840.10045.4.3.4": sha512,

    }
    return algorithms[oid]
}

