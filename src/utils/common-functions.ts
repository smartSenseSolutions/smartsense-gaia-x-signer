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
				'@context': 'https://www.w3.org/2018/credentials/v1',
				type: ['VerifiablePresentation'],
				verifiableCredential: [
					{
						'@context': ['https://www.w3.org/2018/credentials/v1', 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#'],
						type: ['VerifiableCredential'],
						id: didId,
						issuer: didId,
						issuanceDate: new Date().toISOString(),
						credentialSubject: {
							id: participantURL,
							type: 'gx:LegalParticipant',
							'gx:legalName': legalName,
							'gx:legalRegistrationNumber': {
								[`gx:${legalRegistrationType}`]: legalRegistrationNumber
							},
							'gx:headquarterAddress': {
								'gx:countrySubdivisionCode': headquarterAddress
							},
							'gx:legalAddress': {
								'gx:countrySubdivisionCode': legalAddress
							},
							'gx-terms-and-conditions:gaiaxTermsAndConditions': '70c1d713215f95191a11d38fe2341faed27d19e083917bc8732ca4fea4976700'
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
			try {
				const canonized = await jsonld.canonize(payload, {
					algorithm: 'URDNA2015',
					format: 'application/n-quads'
				})
				if (canonized === '') throw new Error('Canonized SD is empty')
				return canonized
			} catch (error) {
				console.log(`❌ Canonizing failed | Error: ${error}`)
				return undefined
			}
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
			try {
				const pubkey = await jose.importJWK(publicKeyJwk, algorithm)
				const result = await jose.compactVerify(jws, pubkey)
				return {
					protectedHeader: result.protectedHeader,
					content: new TextDecoder().decode(result.payload)
				}
			} catch (error) {
				throw new Error(`Signature Verification Failed | error: ${error}`)
			}
		}

		// function to check if private key and did are correct pair by performing encryption- decryption on a dummy message
		async verifyKeyPair(
			issuerDid: string,
			privateKeyUrl: string,
			jose: any,
			resolver: any,
			algorithm: string,
			axios: any,
			he: any,
			flattenEncryptAlgorithm: string,
			flattenEncryptEncoding: string
		): Promise<object> {
			try {
				//retrieve ddo from the did
				const ddo = await resolver.resolve(issuerDid)
				//if ddo not found throw error
				if (!ddo.didDocument) {
					return {
						status: false,
						message: `Couldn't resolve issuerDid`
					}
				} else {
					//dummy message to encrypt
					let message = 'some random message'
					let publicKeyJwk: any
					// get public jwk from ddo
					if (ddo.didDocument?.verificationMethod) {
						publicKeyJwk = ddo.didDocument?.verificationMethod[0].publicKeyJwk
					}
					//import public key from jwk
					const publicKey = await jose.importJWK(publicKeyJwk, algorithm)
					//encrypt the message using the public key
					const jwe = await new jose.FlattenedEncrypt(new TextEncoder().encode(message))
						.setProtectedHeader({ alg: flattenEncryptAlgorithm, enc: flattenEncryptEncoding })
						.encrypt(publicKey)
					// import private key
					const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
					const rsaPrivateKey = await jose.importPKCS8(privateKey as string, algorithm)
					// const rsaPrivateKey = await jose.importPKCS8(process.env.PRIVATE_KEY as string, algorithm)
					// decode the encrypted jwe using private key
					const { plaintext } = await jose.flattenedDecrypt(jwe, rsaPrivateKey)
					// get decoder object
					const decoder = new TextDecoder()
					// return true if dummy message and encrypted message are same, verifying private and public key are a key pair
					return { status: decoder.decode(plaintext) === message, message: '' }
				}
			} catch (e: any) {
				// this error is raised when incorrect private key is used, signifying incorrect keypair
				if (e?.code === 'ERR_JWE_DECRYPTION_FAILED') {
					return { status: false, message: 'Incorrect key pair' }
				} else {
					return { status: false, message: e }
				}
			}
		}

		createVpObj(claims: any): Object {
			let contextUris: string[] = []
			for (const claim of claims) {
				const contextUriArr = claim['@context']
				for (const uri of contextUriArr) {
					if (!contextUris.includes(uri)) {
						contextUris.push(uri)
					}
				}
			}

			const vp = {
				'@context': contextUris,
				type: ['VerifiablePresentation'],
				verifiableCredential: claims
			}
			return vp
		}

		async getDDOfromDID(did: string, resolver: any) {
			try {
				const ddo = await resolver.resolve(did)
				if (!ddo.didDocument.verificationMethod || ddo.didDocument === null || ddo.didResolutionMetadata.error) {
					return undefined
				}
				return ddo
			} catch (error) {
				console.log(`❌ Fetching DDO failed for did: ${did}`)
				return undefined
			}
		}

		async validateSslFromRegistry(certificates: string, axios: any) {
			try {
				// const registryRes = await axios.post(process.env.REGISTRY_TRUST_ANCHOR_URL as string, { certs: certificates })
				// todo - check the response from the registry to be 200
				// return registryRes.status === 200
				return true
			} catch (error) {
				console.log(`❌ Validation from registry failed for certificates | error: ${error}`)
				return false
			}
		}

		async comparePubKeys(certificates: string, publicKeyJwk: any, jose: any) {
			try {
				const pk = await jose.importJWK(publicKeyJwk)
				const spki = await jose.exportSPKI(pk)

				const x509 = await jose.importX509(certificates, 'PS256')
				const spkiX509 = await jose.exportSPKI(x509)

				return spki === spkiX509
			} catch (error) {
				console.log(`❌ Comparing publicKeyJwk and pub key from certificates failed | error: ${error}`)
				return false
			}
		}
	}
}

export const Utils = new CommonFunctions.Utils()
