# ecdsa_icao

This is a pure JS implementation of ECDSA for eMRTD certificates (ICAO 9303 p.12) with explicit ECC parameters 

> [Docs](https://li0ard.github.io/ecdsa_icao)

## Install

```bash
bun add github:li0ard/ecdsa_icao
```

## Example

```ts
import { curveFromECParams } from "@li0ard/ecdsa_icao"

let certificate = new X509Certificate("./example.pem")
let curve = curveFromECParams(certificate).subjectPublicKeyInfo
```