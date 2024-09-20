# ecdsa_icao

This is a pure JS implementation of the signature verification algorithm for eMRTD certificates (ICAO 9303 p.12) with explicit ECC parameters using ECDSA.

## Install

```bash
bun add github:li0ard/ecdsa_icao
```

## Methods

```ts
/**
 * Identify curve by `p` field
 * @param params 
 */
export const identifyCurveByP = (params: ECParameters) => {}

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
```