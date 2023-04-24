# Smart-X-Signer by smartSense

This tool to showcase the capability of smartSense in contact with the Gaia-X economy.
This MVP covers below user case:

1. Create Web Decentralized Identifiers(did)
2. On-boarding in Gaia-x
    1. Create a legal participant
    2. Create a service offer
3. Create a Verifiable credential
4. Create a Verifiable presentation
5. Verify a Verifiable credentials and Verifiable presentations

## Tools and Technologies

1. NodeJS
2. ExpressJS
3. Swagger API Doc

## Flow

### Create a Verifiable presentation

An array of claims (VCs) along with private key URL and holder DID are taken as request parameters. The claims are individually verified using the process described below for verification of verifiable credential and verifiable presentation. If the claims are valid, a signed Verifiable Presentaion object is returned using the provided private key. The verified claims are signed and the proof is attached in the presentation.

### Verify a Verifiable credentials and Verifiable presentations

A verifiable credential or a verifiable presentation is passed as a request parameter for verification.

The passed object is verified by initially checking the proof type is valid. The DDO is resolved from the verification method and the public key is retreived from the DDO. The certificate chain which is retreived from x5u in the public key is checked to ensure that the issuer is GaiaX Trust anchor. Also, the public key of the certificate and DDO are ensured to be the same.

Afterward the verification of credential is performed by canonizing the credential followed by hashing using the public key of the issuer. The hash is added in place of `..` in the proof, verified and decoded using the public key of the issuer. If the decoded result is the same as the proof, the passed credential/ presentation is valid.

If a verifiable presentation is passed, the claims in the presentation are also verified similarly.

## Known issue or improvement

1. Only allowed templates are available for VC and VP.

## Run application
change node version 16.13.1
```Bash
mv env-example .env
npm ci
npm run dev
```


