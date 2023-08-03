import axios from 'axios'
import { DidDocument, Service, LegalRegistrationNumberDto, VerifiableCredentialDto, SignatureDto, VerificationMethod } from '../interface/interface'
import { AppConst, AppMessages } from './constants'
import * as jose from 'jose'
import jsonld from 'jsonld'
class Utils {
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

	generateLegalPerson(participantURL: string, didId: string, legalName: string, headquarterAddress: string, legalAddress: string, legalRegistrationNumberVCUrl: string): object {
		const selfDescription = {
			'@context': 'https://www.w3.org/2018/credentials/v1',
			type: ['VerifiablePresentation'],
			verifiableCredential: [
				{
					'@context': [
						'https://www.w3.org/2018/credentials/v1',
						'https://w3id.org/security/suites/jws-2020/v1',
						'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#'
					],
					type: ['VerifiableCredential'],
					id: didId,
					issuer: didId,
					issuanceDate: new Date().toISOString(),
					credentialSubject: {
						id: participantURL,
						type: 'gx:LegalParticipant',
						'gx:legalName': legalName,
						'gx:legalRegistrationNumber': {
							id: legalRegistrationNumberVCUrl
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

	async generateTermsAndConditions(axios: any, didId: string, tandcsURL: string) {
		// const { text } = (await axios.get(`${process.env.REGISTRY_TRUST_ANCHOR_URL as string}/termsAndConditions`)).data
		const verifiableCredential = {
			'@context': [
				'https://www.w3.org/2018/credentials/v1',
				'https://w3id.org/security/suites/jws-2020/v1',
				'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#'
			],
			type: ['VerifiableCredential'],
			issuanceDate: new Date().toISOString(),
			credentialSubject: {
				'@context': 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#',
				type: 'gx:GaiaXTermsAndConditions',
				// 'gx:termsAndConditions': text,
				'gx:termsAndConditions':
					'The PARTICIPANT signing the Self-Description agrees as follows:\n- to update its descriptions about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the descriptions.\n\nThe keypair used to sign Verifiable Credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).',
				id: tandcsURL
			},
			issuer: didId,
			id: didId
		}
		return verifiableCredential
	}

	async generateRegistrationNumber(axios: any, didId: string, legalRegistrationType: string, legalRegistrationNumber: string, legalRegistrationNumberVCUrl: string) {
		try {
			const request = {
				'@context': ['https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant'],
				type: 'gx:legalRegistrationNumber',
				id: legalRegistrationNumberVCUrl,
				[`gx:${legalRegistrationType}`]: legalRegistrationNumber
			}
			const url = `${process.env.REGISTRATION_SERVICE as string}?vcid=${legalRegistrationNumberVCUrl}`
			const regVC = await axios.post(url, request)
			// console.log(regVC.data)
			return regVC.data
		} catch (error) {
			console.log(`❌ RegistrationNumber failed | Error: ${error}`)
			throw new Error(`❌ RegistrationNumber failed | Error: ${error}`)
		}
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

	async generateProof(
		jsonld: any,
		he: any,
		axios: any,
		jose: any,
		crypto: any,
		verifiableCredential: any,
		privateKeyUrl: string,
		didId: string,
		domain: string,
		tenant: string,
		rsaAlso: string
	) {
		const canonizedSD = await this.normalize(
			jsonld,
			// eslint-disable-next-line
			verifiableCredential
		)
		const hash = this.sha256(crypto, canonizedSD)
		console.log(`📈 Hashed canonized SD ${hash}`)

		// const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
		const privateKey = process.env.PRIVATE_KEY as string
		const proof = await this.createProof(jose, didId, rsaAlso, hash, privateKey)
		console.log(proof ? '🔒 SD signed successfully' : '❌ SD signing failed')
		const x5uURL = tenant ? `https://${domain}/${tenant}/x509CertificateChain.pem` : `https://${domain}/.well-known/x509CertificateChain.pem`
		console.log(x5uURL)
		const certificate = (await axios.get(x5uURL)).data as string
		const publicKeyJwk = await this.generatePublicJWK(jose, rsaAlso, certificate, x5uURL)

		const verificationResult = await this.verify(jose, proof.jws.replace('..', `.${hash}.`), rsaAlso, publicKeyJwk, hash)
		console.log(verificationResult ? '✅ Verification successful' : '❌ Verification failed')
		return proof
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

	async createProof(jose: any, verificationMethod: string, algorithm: string, hash: string, privateKey: string) {
		const proof = {
			type: 'JsonWebSignature2020',
			created: new Date().toISOString(),
			proofPurpose: 'assertionMethod',
			verificationMethod: verificationMethod,
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
			const registryRes = await axios.post(`${process.env.REGISTRY_TRUST_ANCHOR_URL as string}/trustAnchor/chain`, { certs: certificates })
			return registryRes.status === 200
		} catch (error) {
			console.log(`❌ Validation from registry failed for certificates | error: ${error}`)
			return false
		}
	}

	async validateSslFromRegistryWithUri(uri: string, axios: any) {
		try {
			const registryRes = await axios.post(`${process.env.REGISTRY_TRUST_ANCHOR_URL as string}/trustAnchor/chain/file`, { uri: uri })
			const result = registryRes?.data?.result
			return result
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
		// console.log(result)
		return result
	}

	async issueRegistrationNumberVC(axios: any, request: LegalRegistrationNumberDto) {
		try {
			request.id = request.id.replace('#', '%23')
			// console.log(request)
			// console.log(JSON.stringify(request))
			const url = `${process.env.REGISTRATION_SERVICE as string}?vcid=${request.id}`
			const regVC = await axios.post(url, request)
			// console.log(regVC.data)
			return regVC.data
		} catch (error) {
			console.log(`❌ RegistrationNumber failed | Error: ${error}`)
			throw new Error(`❌ RegistrationNumber failed | Error: ${error}`)
		}
	}

	async addProof(
		jsonld: any,
		axios: any,
		jose: any,
		crypto: any,
		verifiableCredential: VerifiableCredentialDto,
		privateKey: string,
		verificationMethod: string,
		rsaAlso: string,
		x5uURL: string
	) {
		const canonizedSD = await this.normalize(
			jsonld,
			// eslint-disable-next-line
			verifiableCredential
		)
		const hash = this.sha256(crypto, canonizedSD)
		console.log(`📈 Hashed canonized SD ${hash}`)

		const proof = await this.createProof(jose, verificationMethod, rsaAlso, hash, privateKey)
		console.log(proof ? '🔒 SD signed successfully' : '❌ SD signing failed')

		const certificate = (await axios.get(x5uURL)).data as string
		const publicKeyJwk = await this.generatePublicJWK(jose, rsaAlso, certificate, x5uURL)

		const verificationResult = await this.verify(jose, proof.jws.replace('..', `.${hash}.`), rsaAlso, publicKeyJwk, hash)
		console.log(verificationResult ? '✅ Verification successful' : '❌ Verification failed')
		return proof
	}

	async getPublicKeys(ddo: any) {
		const { verificationMethod, id } = ddo
		const jwk = verificationMethod.find((method: any) => method.id.startsWith(id))
		if (!jwk) throw new Error(`verificationMethod ${verificationMethod} not found in did document`)

		const { publicKeyJwk } = jwk
		if (!publicKeyJwk) throw new Error(`Could not load JWK for ${verificationMethod}`)

		const { x5u } = publicKeyJwk
		if (!publicKeyJwk.x5u) throw new Error(`The x5u parameter is expected to be set in the JWK for ${verificationMethod}`)

		return { x5u, publicKeyJwk }
	}

	createVP(vcs: any) {
		return {
			'@context': 'https://www.w3.org/2018/credentials/v1',
			type: ['VerifiablePresentation'],
			verifiableCredential: vcs
		}
	}

	/**
	 * @dev - common function to fetch ParticipantJson from participantUrl
	 *
	 */
	fetchParticipantJson = async (participantUrl: string) => {
		// eslint-disable-next-line no-useless-catch
		try {
			const participantJson = (await axios.get(participantUrl)).data
			return participantJson
		} catch (error) {
			throw error
		}
	}

	/**
	 * @dev takes the credential and proof, and verifies the signature is valid or not
	 * @param credentialContent the credential part which will be hashed for proof
	 * @param proof the proof obj
	 * @returns boolean - true if the signature is verified
	 */

	async verification(credentialContent: VerifiableCredentialDto, proof: SignatureDto, checkSSLwithRegistry: boolean, resolver: any) {
		// eslint-disable-next-line no-useless-catch
		try {
			// check if proof is of type JsonWebSignature2020
			if (proof.type !== 'JsonWebSignature2020') {
				console.log(`❌ signature type: '${proof.type}' not supported`)
				throw new Error(`signature type: '${proof.type}' not supported`)
			}

			// get the DID Document
			const ddo = await this.getDDOfromDID(proof.verificationMethod, resolver)
			if (!ddo) {
				console.log(`❌ DDO not found for given did: '${proof.verificationMethod}' in proof`)
				throw new Error(`DDO not found for given did: '${proof.verificationMethod}' in proof`)
			}

			// get the public keys from the DID Document
			// eslint-disable-next-line no-unsafe-optional-chaining
			const verMethod = ddo?.didDocument?.verificationMethod?.find((verMethod: VerificationMethod) => verMethod.controller == proof.verificationMethod)
			const publicKeyJwk = verMethod?.publicKeyJwk
			if (!publicKeyJwk) {
				throw new Error('publicKeyJwk not found in ddo')
			}
			const x5u = publicKeyJwk?.x5u
			if (!x5u) {
				throw new Error('x5u not found in ddo')
			}
			// get the SSL certificates from x5u url
			const certificates = (await axios.get(x5u)).data as string
			if (!certificates) {
				throw new Error('ssl certificate not found')
			}
			if (checkSSLwithRegistry) {
				// signature check against Gaia-x registry
				const registryRes = await this.validateSslFromRegistryWithUri(x5u, axios)
				if (!registryRes) {
					throw new Error('Certificate validation failed')
				}
			}

			//check weather the public key from DDO(which is fetched from did) matches with the certificates of x5u(fetched from ddo)
			const comparePubKey = await this.comparePubKeys(certificates, publicKeyJwk, jose)
			if (!comparePubKey) {
				console.log(`❌ Public Keys Mismatched`)
				throw new Error('Public Key Mismatched')
			}

			// // normalize/canonize the credentialContent
			const canonizedCredential = await this.normalize(
				jsonld,
				// eslint-disable-next-line
				credentialContent
			)

			if (typeof canonizedCredential === 'undefined') {
				console.log(`❌ Normalizing Credential Failed`)
				throw new Error('Normalizing Credential Failed')
			}

			// TODO: explore the isValidityCheck here, to include the jws in the hash - GX Compliance check signature

			// hash the normalized credential
			const hash = await this.sha256(crypto, canonizedCredential)

			// verify Signature by retrieving the hash and then comparing it
			const verificationResult = await this.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
			console.log(verificationResult ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)
			return verificationResult
		} catch (error) {
			throw error
		}
	}
}

export default new Utils()
