module Util {
  export function generateDID(didId: string, publicKeyJwk: any): unknown {
    const did = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: didId,
      verificationMethod: [
        {
          "@context": "https://w3c-ccg.github.io/lds-jws2020/contexts/v1/",
          id: didId,
          type: "JsonWebKey2020",
          controller: didId,
          publicKeyJwk: publicKeyJwk,
        },
      ],
      assertionMethod: [`${didId}#JWK2020-RSA`],
    };

    // const data = JSON.stringify(did, null, 2);
    return did;
  }

  export function generateLegalPerson(
    didId: string,
    legalName: string,
    legalRegistrationType: string,
    legalRegistrationNumber: string,
    headquarterAddress: string,
    legalAddress: string
  ): object {
    const selfDescription = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/termsandconditions#",
        "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant#",
      ],
      type: ["VerifiablePresentation"],
      verifiableCredential: [
        {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/termsandconditions#",
            "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant#",
          ],
          type: ["VerifiableCredential", "gx:LegalParticipant"],
          id: didId,
          issuer: didId,
          issuanceDate: new Date().toISOString(),
          credentialSubject: {
            id: didId,
            "gx:legalName": legalName,
            "gx:legalRegistrationNumber": {
              [legalRegistrationType]: legalRegistrationNumber,
            },
            "gx:headquarterAddress": {
              "gx:countrySubdivisionCode": headquarterAddress,
            },
            "gx:legalAddress": {
              "gx:countrySubdivisionCode": legalAddress,
            },
          },
        },
      ],
    };
    return selfDescription;
  }

  export async function generatePublicJWK(
    jose: any,
    algorithm: string,
    certificate: string,
    x5uURL: string
  ): Promise<any> {
    try {
      const x509 = await jose.importX509(certificate, algorithm);
      const publicKeyJwk = await jose.exportJWK(x509);
      publicKeyJwk.alg = algorithm;
      publicKeyJwk.x5u = x5uURL;
      return publicKeyJwk;
    } catch (e) {
      throw e;
    }
  }

  export async function normalize(jsonld: any, payload: object) {
    const canonized = await jsonld.canonize(payload, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
    });
    if (canonized === "") throw new Error("Canonized SD is empty");
    return canonized;
  }

  export function sha256(crypto: any, input: object) {
    return crypto.createHash("sha256").update(input).digest("hex");
  }

  export async function createProof(
    jose: any,
    didId: string,
    algorithm: string,
    hash: string,
    privateKey: string
  ) {
    const proof = {
      type: "JsonWebSignature2020",
      created: new Date().toISOString(),
      proofPurpose: "assertionMethod",
      verificationMethod: didId,
      jws: await sign(jose, algorithm, hash, privateKey),
    };

    return proof;
  }

  async function sign(
    jose: any,
    algorithm: string,
    hash: string,
    privateKey: string
  ) {
    const rsaPrivateKey = await jose.importPKCS8(privateKey, algorithm);
    try {
      const jws = await new jose.CompactSign(new TextEncoder().encode(hash))
        .setProtectedHeader({ alg: algorithm, b64: false, crit: ["b64"] })
        .sign(rsaPrivateKey);
      return jws;
    } catch (error) {
      throw error;
    }
  }

  export async function verify(
    jose: any,
    jws: string,
    algorithm: string,
    publicKeyJwk: string
  ) {
    const pubkey = await jose.importJWK(publicKeyJwk, algorithm);
    try {
      const result = await jose.compactVerify(jws, pubkey);

      return {
        protectedHeader: result.protectedHeader,
        content: new TextDecoder().decode(result.payload),
      };
    } catch (error) {
      throw error;
    }
  }
}
export = Util;
