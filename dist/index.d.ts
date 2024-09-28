import { type CurveFn } from "@noble/curves/abstract/weierstrass";
import type { Hash } from "@noble/hashes/utils";
import { type ECParameters } from "@peculiar/asn1-ecc";
/**
 * Parse certificate EC parameters and generate curve object
 * @param params [Public key parameters](https://github.com/PeculiarVentures/asn1-schema/blob/master/packages/ecc/src/ec_parameters.ts)
 */
export declare const curveFromECParams: (params: ECParameters) => CurveFn;
export interface HashFn {
    (msg: Uint8Array | string, opts?: any): Uint8Array;
    outputLen: number;
    blockLen: number;
    create(): Hash<any>;
}
/**
 * Get hash function by signature algorithm OID
 * @param oid OID of signature algorithm
 */
export declare const hashFromECDSAOID: (oid: string) => HashFn;
