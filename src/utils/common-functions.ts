namespace CommonFunctions {
	export class Utils {
		generateDID(didId: string, publicKeyJwk: any): unknown {
			const did = {
				'@context': ['https://www.w3.org/ns/did/v1'],
				id: didId,
				verificationMethod: [
					{
						'@context': 'https://w3c-ccg.github.io/lds-jws2020/contexts/v1/',
						id: didId,
						type: 'JsonWebKey2020',
						controller: didId,
						publicKeyJwk: publicKeyJwk
					}
				],
				assertionMethod: [`${didId}#JWK2020-RSA`]
			}

			// const data = JSON.stringify(did, null, 2);
			return did
		}

		generateLegalPerson(
			participantURL: string,
			didId: string,
			legalName: string,
			legalRegistrationType: string,
			legalRegistrationNumber: string,
			headquarterAddress: string,
			legalAddress: string
		): object {
			const selfDescription = {
				'@context': [
					'https://www.w3.org/2018/credentials/v1',
					'https://registry.lab.gaia-x.eu/main/api/trusted-shape-registry/v1/shapes/jsonld/termsandconditions#',
					'https://registry.lab.gaia-x.eu/main/api/trusted-shape-registry/v1/shapes/jsonld/participant#'
				],
				type: ['VerifiablePresentation'],
				verifiableCredential: [
					{
						'@context': [
							'https://www.w3.org/2018/credentials/v1',
							'https://registry.lab.gaia-x.eu/main/api/trusted-shape-registry/v1/shapes/jsonld/termsandconditions#',
							'https://registry.lab.gaia-x.eu/main/api/trusted-shape-registry/v1/shapes/jsonld/participant#'
						],
						type: ['VerifiableCredential', 'gx:LegalParticipant'],
						id: didId,
						issuer: didId,
						issuanceDate: new Date().toISOString(),
						credentialSubject: {
							id: participantURL,
							'gx:legalName': legalName,
							'gx:legalRegistrationNumber': {
								[`gx:${legalRegistrationType}`]: legalRegistrationNumber
							},
							'gx:headquarterAddress': {
								'gx:countrySubdivisionCode': headquarterAddress
							},
							'gx:legalAddress': {
								'gx:countrySubdivisionCode': legalAddress
							}
						}
					}
				]
			}
			return selfDescription
		}

		async generatePublicJWK(jose: any, algorithm: string, certificate: string, x5uURL: string): Promise<any> {
			const x509 = await jose.importX509(certificate, algorithm)
			const publicKeyJwk = await jose.exportJWK(x509)
			publicKeyJwk.alg = algorithm
			publicKeyJwk.x5u = x5uURL
			return publicKeyJwk
		}

		async normalize(jsonld: any, payload: object) {
			const canonized = await jsonld.canonize(payload, {
				algorithm: 'URDNA2015',
				format: 'application/n-quads'
			})
			if (canonized === '') throw new Error('Canonized SD is empty')
			return canonized
		}

		sha256(crypto: any, input: object) {
			return crypto.createHash('sha256').update(input).digest('hex')
		}

		async createProof(jose: any, didId: string, algorithm: string, hash: string, privateKey: string) {
			const proof = {
				type: 'JsonWebSignature2020',
				created: new Date().toISOString(),
				proofPurpose: 'assertionMethod',
				verificationMethod: didId,
				jws: await this.sign(jose, algorithm, hash, privateKey)
			}

			return proof
		}

		async sign(jose: any, algorithm: string, hash: string, privateKey: string) {
			const rsaPrivateKey = await jose.importPKCS8(privateKey, algorithm)
			const txtEncoder = new TextEncoder().encode(hash)
			const jws = await new jose.CompactSign(txtEncoder).setProtectedHeader({ alg: algorithm, b64: false, crit: ['b64'] }).sign(rsaPrivateKey)
			return jws
		}

		async verify(jose: any, jws: string, algorithm: string, publicKeyJwk: string) {
			const pubkey = await jose.importJWK(publicKeyJwk, algorithm)
			const result = await jose.compactVerify(jws, pubkey)
			return {
				protectedHeader: result.protectedHeader,
				content: new TextDecoder().decode(result.payload)
			}
		}
		async verifyKeyPair(issuerDid: string, privateKeyUrl: string, jose: any, resolver: any, algorithm: string): Promise<object> {
			try {
				const ddo = await resolver.resolve(issuerDid)
				if (!ddo.didDocument) {
					return {
						status: false,
						message: `Couldn't resolve issuerDid`
					}
				} else {
					let message = 'some random message'
					let publicKeyJwk: any

					if (ddo.didDocument?.verificationMethod) {
						publicKeyJwk = ddo.didDocument?.verificationMethod[0].publicKeyJwk
					}
					const publicKey = await jose.importJWK(publicKeyJwk, algorithm)
					const jwe = await new jose.FlattenedEncrypt(new TextEncoder().encode(message)).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(publicKey)
					// const privateKey = (await axios.get(privateKeyUrl)).data as string;
					const privateKey = await jose.importPKCS8(process.env.PRIVATE_KEY as string, algorithm)
					const { plaintext } = await jose.flattenedDecrypt(jwe, privateKey)
					const decoder = new TextDecoder()
					return { status: decoder.decode(plaintext) === message, message: '' }
				}
			} catch (e: any) {
				if (e?.code === 'ERR_JWE_DECRYPTION_FAILED') {
					return { status: false, message: 'Incorrect key pair' }
				} else {
					return { status: false, message: e }
				}
			}
		}
	}
}

export const Utils = new CommonFunctions.Utils()
