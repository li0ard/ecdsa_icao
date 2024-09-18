import { createCurve } from "@noble/curves/_shortw_utils";
import { Field } from "@noble/curves/abstract/modular";
import { sha1 } from "@noble/hashes/sha1";
import { sha224, sha256 } from "@noble/hashes/sha256";
import { sha384, sha512 } from "@noble/hashes/sha512";
import { ECParameters } from "@peculiar/asn1-ecc";
import TLV from "node-tlv";
/**
 * Convert buffer to BigInt
 * @param data Input buffer
 */
const bufToBigInt = (data) => {
    return BigInt(`0x${data.toString("hex")}`);
};
/**
 * Parse certificate EC parameters and generate curve object
 * @param params
 * @param lowS
 */
export const curveFromECParams = (params, lowS = false) => {
    if (!params.specifiedCurve)
        throw new Error("Only explicit ECC parameters supported");
    if (params.specifiedCurve.fieldID.fieldType != "1.2.840.10045.1.1")
        throw new Error("Only explicit [X9.62] schema supported");
    let base = Buffer.from(params.specifiedCurve.base.buffer).subarray(1);
    return createCurve({
        a: bufToBigInt(Buffer.from(params.specifiedCurve.curve.a)),
        b: bufToBigInt(Buffer.from(params.specifiedCurve.curve.b)),
        Fp: Field(bufToBigInt(TLV.parse(Buffer.from(params.specifiedCurve.fieldID.parameters)).bValue)),
        n: bufToBigInt(Buffer.from(params.specifiedCurve.order)),
        Gx: bufToBigInt(base.subarray(0, base.length / 2)),
        Gy: bufToBigInt(base.subarray(base.length / 2)),
        h: BigInt(params.specifiedCurve.cofactor),
        lowS: lowS
    }, sha512); // random hash, because it is not used here, but it is needed as a parameter
};
/**
 * Get hash function by signature algorithm OID
 * @param oid Signature algorithm OID
 */
export const hashFromECDSAOID = (oid) => {
    let algorithms = {
        "1.2.840.10045.4.1": sha1,
        "1.2.840.10045.4.3.1": sha224,
        "1.2.840.10045.4.3.2": sha256,
        "1.2.840.10045.4.3.3": sha384,
        "1.2.840.10045.4.3.4": sha512,
    };
    return algorithms[oid];
};
/**
 * Verify signature by public key and hash of data
 * @param curve Curve object
 * @param pk Public key
 * @param hash Hash of data
 * @param sig Signature
 */
export const verify = (curve, pk, hash, sig) => {
    return curve.verify(sig, hash, pk);
};
