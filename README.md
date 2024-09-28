# ecdsa_icao

This is a pure JS implementation of ECDSA features for eMRTD certificates (ICAO 9303 p.12) with explicit ECC parameters 

> [Docs](https://li0ard.github.io/ecdsa_icao)

## Install

```bash
bun add github:li0ard/ecdsa_icao
```

## Example

```ts
import { curveFromECParams } from "@li0ard/ecdsa_icao"
import { AsnConvert } from "@peculiar/asn1-schema"
import { CertificateChoices } from "@peculiar/asn1-cms"
import fs from "fs"

let certificate = AsnConvert.parse(fs.readFileSync("./cert.der"), CertificateChoices)
let curve = curveFromECParams(certificate.tbsCertificate.subjectPublicKeyInfo.parameters)
```