import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { ECParameters } from "@peculiar/asn1-ecc";
/**
 * Identify curve by `p` field
 * @param params
 */
export declare const identifyCurveByP: (params: ECParameters) => any;
/**
 * Parse certificate EC parameters and generate curve object
 * @param params
 * @param lowS
 */
export declare const curveFromECParams: (params: ECParameters, lowS?: boolean) => Readonly<{
    create: (hash: import("@noble/curves/abstract/utils").CHash) => import("@noble/curves/abstract/weierstrass").CurveFn;
    CURVE: ReturnType<(curve: import("@noble/curves/abstract/weierstrass").CurveType) => Readonly<{
        readonly nBitLength: number;
        readonly nByteLength: number;
        readonly Fp: import("@noble/curves/abstract/modular").IField<bigint>;
        readonly n: bigint;
        readonly h: bigint;
        readonly hEff?: bigint;
        readonly Gx: bigint;
        readonly Gy: bigint;
        readonly allowInfinityPoint?: boolean;
        readonly a: bigint;
        readonly b: bigint;
        readonly allowedPrivateKeyLengths?: readonly number[];
        readonly wrapPrivateKey?: boolean;
        readonly endo?: {
            beta: bigint;
            splitScalar: (k: bigint) => {
                k1neg: boolean;
                k1: bigint;
                k2neg: boolean;
                k2: bigint;
            };
        };
        readonly isTorsionFree?: ((c: import("@noble/curves/abstract/weierstrass").ProjConstructor<bigint>, point: import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>) => boolean) | undefined;
        readonly clearCofactor?: ((c: import("@noble/curves/abstract/weierstrass").ProjConstructor<bigint>, point: import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>) => import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>) | undefined;
        readonly hash: import("@noble/curves/abstract/utils").CHash;
        readonly hmac: (key: Uint8Array, ...messages: Uint8Array[]) => Uint8Array;
        readonly randomBytes: (bytesLength?: number) => Uint8Array;
        lowS: boolean;
        readonly bits2int?: (bytes: Uint8Array) => bigint;
        readonly bits2int_modN?: (bytes: Uint8Array) => bigint;
        readonly p: bigint;
    }>>;
    getPublicKey: (privateKey: import("@noble/curves/abstract/utils").PrivKey, isCompressed?: boolean) => Uint8Array;
    getSharedSecret: (privateA: import("@noble/curves/abstract/utils").PrivKey, publicB: import("@noble/curves/abstract/utils").Hex, isCompressed?: boolean) => Uint8Array;
    sign: (msgHash: import("@noble/curves/abstract/utils").Hex, privKey: import("@noble/curves/abstract/utils").PrivKey, opts?: import("@noble/curves/abstract/weierstrass").SignOpts) => import("@noble/curves/abstract/weierstrass").RecoveredSignatureType;
    verify: (signature: import("@noble/curves/abstract/utils").Hex | {
        r: bigint;
        s: bigint;
    }, msgHash: import("@noble/curves/abstract/utils").Hex, publicKey: import("@noble/curves/abstract/utils").Hex, opts?: import("@noble/curves/abstract/weierstrass").VerOpts) => boolean;
    ProjectivePoint: import("@noble/curves/abstract/weierstrass").ProjConstructor<bigint>;
    Signature: import("@noble/curves/abstract/weierstrass").SignatureConstructor;
    utils: {
        normPrivateKeyToScalar: (key: import("@noble/curves/abstract/utils").PrivKey) => bigint;
        isValidPrivateKey(privateKey: import("@noble/curves/abstract/utils").PrivKey): boolean;
        randomPrivateKey: () => Uint8Array;
        precompute: (windowSize?: number, point?: import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>) => import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>;
    };
}>;
/**
 * Get hash function by signature algorithm OID
 * @param oid Signature algorithm OID
 */
export declare const hashFromECDSAOID: (oid: string) => typeof sha1 | typeof sha256 | typeof sha512;
