import { DidDocument, Service } from '../interface/interface'

namespace CommonFunctions {
	export class Utils {
		generateDID(didId: string, publicKeyJwk: any, services: Service[]): unknown {
			const did: DidDocument = {
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
			if (services) {
				for (let index = 0; index < services.length; index++) {
					if (!did.hasOwnProperty('service')) {
						did['service'] = []
					}
					const service = services[index]
					service['id'] = `${didId}#${services[index].type.toLocaleLowerCase()}`
					did.service?.push(service)
				}
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

		generateServiceOffer(participantURL: string, didId: string, serviceComplianceUrl: string, data: any): object {
			const { serviceName, description, policyUrl, termsAndConditionsUrl, termsAndConditionsHash, formatType, accessType, requestType } = data
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
							id: serviceComplianceUrl,
							'gx:name': serviceName,
							'gx:description': description,
							type: 'gx:ServiceOffering',
							'gx:providedBy': {
								id: participantURL
							},
							'gx:policy': policyUrl,
							'gx:termsAndConditions': {
								'gx:URL': termsAndConditionsUrl,
								'gx:hash': termsAndConditionsHash
							},
							'gx:dataAccountExport': {
								'gx:requestType': requestType,
								'gx:accessType': accessType,
								'gx:formatType': formatType
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

		async verify(jose: any, jws: string, algorithm: string, publicKeyJwk: string, hash: string) {
			try {
				const pubkey = await jose.importJWK(publicKeyJwk, algorithm)
				const result = await jose.compactVerify(jws, pubkey)
				// const protectedHeader = result.protectedHeader
				const content = new TextDecoder().decode(result.payload)
				return content === hash
			} catch (error) {
				console.log(`❌ Signature Verification Failed | error: ${error}`)
				return false
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

		async validateSslFromRegistry(certificates: any, axios: any) {
			try {
				certificates = certificates.replace(/\n/gm, '') || undefined
				const registryRes = await axios.post(process.env.REGISTRY_TRUST_ANCHOR_URL as string, { certs: certificates })
				return registryRes.status === 200
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

		IsValidURL = (str: string) => {
			const urlRegex =
				'^(?!mailto:)(?:(?:http|https|ftp)://)(?:\\S+(?::\\S*)?@)?(?:(?:(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[0-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)(?:\\.(?:[a-z\\u00a1-\\uffff0-9]+-?)*[a-z\\u00a1-\\uffff0-9]+)*(?:\\.(?:[a-z\\u00a1-\\uffff]{2,})))|localhost)(?::\\d{2,5})?(?:(/|\\?|#)[^\\s]*)?$'
			const url = new RegExp(urlRegex, 'i')
			const result = str.length < 2083 && url.test(str)
			console.log(result)
			return result
		}
	}
}

export const Utils = new CommonFunctions.Utils()
