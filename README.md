# ecdsa_icao

This is a pure JS implementation of the signature verification algorithm for eMRTD certificates (ICAO 9303 p.12) with explicit ECC parameters using ECDSA.

## Install

```bash
bun add github:li0ard/ecdsa_icao
```

## Methods

```ts
/**
 * Parse certificate EC parameters and generate curve object
 * @param params 
 */
export const curveFromECParams = (params: ECParameters) => {}

/**
 * Get hash function by signature algorithm OID
 * @param oid Signature algorithm OID
 */
export const hashFromECDSAOID = (oid: string): typeof sha1 | typeof sha256 | typeof sha512 => {}

/**
 * Verify signature by public key and hash of data
 * @param curve Curve object
 * @param pk Public key
 * @param hash Hash of data
 * @param sig Signature
 */
export const verify = (curve: any, pk: Buffer, hash: Buffer, sig: Buffer): boolean => {}
```