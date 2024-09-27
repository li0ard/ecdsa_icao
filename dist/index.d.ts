import { type CurveFn } from "@noble/curves/abstract/weierstrass";
import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { type ECParameters } from "@peculiar/asn1-ecc";
/**
 * Parse certificate EC parameters and generate curve object
 * @param params Public key parameters
 * @param lowS Low order
 */
export declare const curveFromECParams: (params: ECParameters, lowS?: boolean) => CurveFn;
/**
 * Get hash function by signature algorithm OID
 * @param oid OID of signature algorithm
 */
export declare const hashFromECDSAOID: (oid: string) => typeof sha1 | typeof sha256 | typeof sha512;
