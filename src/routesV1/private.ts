import axios from 'axios'
import crypto, { createHash } from 'crypto'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'
import { Resolver } from 'did-resolver'
import express, { Request, Response } from 'express'
import { check, validationResult } from 'express-validator'
import web from 'web-did-resolver'
import * as jose from 'jose'
import jsonld from 'jsonld'
import { ComplianceCredential, SignatureDto, VerifiableCredentialDto, VerificationMethod, VerificationStatus } from '../interface/interface'

const webResolver = web.getResolver()
const resolver = new Resolver(webResolver)
export const privateRoute = express.Router()

privateRoute.post(
	'/LegalParticipantOnGaiaX',
	check('issuer').not().isEmpty().trim().escape(),
	check('verificationMethod').not().isEmpty().trim().escape(),
	check('privateKey').not().isEmpty().trim().escape(),
	check('vcs.legalParticipant').isObject(),
	check('vcs.legalRegistrationNumber').isObject(),
	check('vcs.gaiaXTermsAndConditions').isObject(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const { issuer, verificationMethod, vcs } = req.body
			let { privateKey } = req.body
			let { legalParticipant, legalRegistrationNumber, gaiaXTermsAndConditions } = vcs
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.VP_VALIDATION
				})
			} else {
				const ddo = await Utils.getDDOfromDID(issuer, resolver)
				if (!ddo) {
					console.log(`❌ DDO not found for given did: '${issuer}' in proof`)
					res.status(400).json({
						error: `DDO not found for given did: '${issuer}' in proof`
					})
					return
				}
				const { x5u } = await Utils.getPublicKeys(ddo.didDocument)
				privateKey = Buffer.from(privateKey, 'base64').toString('ascii')
				// privateKey = process.env.PRIVATE_KEY as string

				const legalRegistrationNumberVc = await Utils.issueRegistrationNumberVC(axios, legalRegistrationNumber)
				const vcs = [legalParticipant, legalRegistrationNumberVc, gaiaXTermsAndConditions]
				for (let index = 0; index < vcs.length; index++) {
					const vc = vcs[index]
					if (!vc.hasOwnProperty('proof')) {
						const proof = await Utils.addProof(jsonld, axios, jose, crypto, vc, privateKey, verificationMethod, AppConst.RSA_ALGO, x5u)
						vcs[index].proof = proof
					}
				}
				const selfDescription = Utils.createVP(vcs)
				const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string, selfDescription)).data
				// // const complianceCredential = {}
				console.log(complianceCredential ? '🔒 SD signed successfully (compliance service)' : '❌ SD signing failed (compliance service)')
				// // await publisherService.publishVP(complianceCredential);
				const completeSd = {
					selfDescriptionCredential: selfDescription,
					complianceCredential: complianceCredential
				}

				res.status(200).json({
					data: { verifiableCredential: completeSd },
					message: AppMessages.VP_SUCCESS
				})
			}
		} catch (e) {
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.VP_FAILED
			})
		}
	}
)

privateRoute.post(
	'/service-offering/gx',
	check('privateKey').not().isEmpty().trim().escape(),
	check('legalParticipant')
		.not()
		.isEmpty()
		.trim()
		.custom(async (value) => {
			if (!Utils.IsValidURL(value)) {
				console.error(`❌ Invalid legal participant self description url format`)
				throw new Error('Invalid legal participant self description url format')
			}
		}),
	check('vcs.serviceOffering').isObject(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			let { privateKey } = req.body
			const {
				legalParticipantSD,
				vcs: { serviceOffering }
			} = req.body
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.SD_SIGN_VALIDATION_FAILED
				})
			} else {
				const legalParticipant = (await axios.get(legalParticipantSD)).data
				const vcs = {}
				privateKey = Buffer.from(privateKey, 'base64').toString('ascii')
				res.status(200).json({
					data: { serviceOffering },
					message: AppMessages.SD_SIGN_SUCCESS
				})
			}
		} catch (e) {
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.SD_SIGN_FAILED
			})
		}
	}
)

privateRoute.post(
	'/verifyLegalParticipant',
	check('policies')
		.isArray()
		.exists()
		.custom((obj) => {
			if (obj.length == 0) {
				return false
			}
			for (const policy of obj) {
				if (!AppConst.VERIFY_LP_POLICIES.includes(policy)) {
					return false
				}
			}

			return true
		}),
	check('participantUrl').exists().isString().isURL(),
	async (req: Request, res: Response): Promise<void> => {
		/* Request Body :
		 * 1. Participant URL : EG . https://greenworld.proofsense.in/.well-known/participant.json
		 */
		//todo : compliance check is remaining
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} of param '${errorsArr[0].param}'`,
					message: AppMessages.SIG_VERIFY_VALIDATION
				})
			} else {
				const { participantUrl, policies } = req.body
				const verificationStatus: VerificationStatus = {
					valid: false
				}

				console.log('fetching participant json...')
				// const participantJson = await Utils.fetchParticipantJson(participantUrl)
				const participantJson: any = {
					selfDescriptionCredential: {
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
								id: 'did:web:greenworld.proofsense.in',
								issuer: 'did:web:greenworld.proofsense.in',
								issuanceDate: '2023-07-28T11:13:53.734Z',
								credentialSubject: {
									id: 'https://greenworld.proofsense.in/.well-known/participant.json#0',
									type: 'gx:LegalParticipant',
									'gx:legalName': 'Green World',
									'gx:legalRegistrationNumber': {
										id: 'https://greenworld.proofsense.in/.well-known/participant.json#1'
									},
									'gx:headquarterAddress': {
										'gx:countrySubdivisionCode': 'BE-BRU'
									},
									'gx:legalAddress': {
										'gx:countrySubdivisionCode': 'BE-BRU'
									}
								},
								proof: {
									type: 'JsonWebSignature2020',
									created: '2023-07-31T11:47:29.107Z',
									proofPurpose: 'assertionMethod',
									verificationMethod: 'did:web:greenworld.proofsense.in',
									jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..JGOf4c0q0LkWbRvKZkpCdjGKvdWMrBHMVwXQ2HIxrXKJ8wHRXGvPonvVhbQHcm6WLsYeuDpS3JiDCVnBJxYMYiGI1iE7UbzS7zidhOJxdjqhN0vhezRTL0rgb326Em6hAF5LLVBKhW1YvhnQwoFaJ-iGVYVjQ1zxe1ohVDfDOfqI9wAEFdorQ7_nr4ZD-RmvnfvRykmXxr5VGjyFyTVZ8ZSeeDVYizscNapAkdo2iOLfLvcwxYZhC_mzASuTWHKMm1avSxQNVF3SB7ZcNoMIe3PqE6x5lKZtReiwoEUdI3_WoarQn8NmRC2GB0Hz8lLj1XcZbI9gBEacQ6uzbk-MZQ'
								}
							},
							{
								'@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
								type: 'VerifiableCredential',
								id: 'https://greenworld.proofsense.in/.well-known/participant.json#1',
								issuer: 'did:web:registration.lab.gaia-x.eu:development',
								issuanceDate: '2023-07-31T11:47:23.611Z',
								credentialSubject: {
									'@context': 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#',
									type: 'gx:legalRegistrationNumber',
									id: 'https://greenworld.proofsense.in/.well-known/participant.json#1',
									'gx:leiCode': '9695007586GCAKPYJ703',
									'gx:leiCode-countryCode': 'FR'
								},
								evidence: [
									{
										'gx:evidenceURL': 'https://api.gleif.org/api/v1/lei-records/',
										'gx:executionDate': '2023-07-31T11:47:23.611Z',
										'gx:evidenceOf': 'gx:leiCode'
									}
								],
								proof: {
									type: 'JsonWebSignature2020',
									created: '2023-07-31T11:47:24.471Z',
									proofPurpose: 'assertionMethod',
									verificationMethod: 'did:web:registration.lab.gaia-x.eu:development#X509-JWK2020',
									jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..V8mpPyGpzHsoHLA6GcCEhJYrTscV1EO-b9XbO5wf22eqM5tj6GCgNqaN8MQmA7MZWiq5NAf9KieHEPtpjJMsOJUKvp7d66iO6ylXzLMwEyte1fMOE_tGJdL3PPrQbsr3j-q3-aGv9wdp7jTJRksMliU2P9-JUpCmqr8JApmnv0Ndxg-hFl6VzrUxJdOEaHuuqo71LBfULHzsMNT0RALjRzN9FbUTO0sTNv5HzHqL1uMPuv1GzIICRG1PyN8VZWI6VXCI0aNcd7AP9D3rhmazmbLfxHED1blJ5eAf5fdJ61nDVpxbS09Pqj9zRSSlZJ0DEaq4Fn_M4g_1RbHrW6Q8iw'
								}
							},
							{
								'@context': [
									'https://www.w3.org/2018/credentials/v1',
									'https://w3id.org/security/suites/jws-2020/v1',
									'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#'
								],
								type: ['VerifiableCredential'],
								issuanceDate: '2023-07-28T11:13:56.533Z',
								credentialSubject: {
									'@context': 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#',
									type: 'gx:GaiaXTermsAndConditions',
									'gx:termsAndConditions':
										'The PARTICIPANT signing the Self-Description agrees as follows:\n- to update its descriptions about any changes, be it technical, organizational, or legal - especially but not limited to contractual in regards to the indicated attributes present in the descriptions.\n\nThe keypair used to sign Verifiable Credentials will be revoked where Gaia-X Association becomes aware of any inaccurate statements in regards to the claims which result in a non-compliance with the Trust Framework and policy rules defined in the Policy Rules and Labelling Document (PRLD).',
									id: 'https://greenworld.proofsense.in/.well-known/participant.json#2'
								},
								issuer: 'did:web:greenworld.proofsense.in',
								id: 'did:web:greenworld.proofsense.in',
								proof: {
									type: 'JsonWebSignature2020',
									created: '2023-07-31T11:47:31.186Z',
									proofPurpose: 'assertionMethod',
									verificationMethod: 'did:web:greenworld.proofsense.in',
									jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..FhIctfvYnWlNaUVCduHe9sPSOLZUyfwuz6EbMbwtN1DYhRD0P9fCHJfKbF5TwWI9i2S0rF2LlM3lXK00RxNJN2qFTpeydR01kxDzYZrlEUZO7xXyy8XdYxwZaEwXRfSrbNkKI1AcsHLoANofo460udlIAEj9hAqHvM4tS05ZMIx8jI1a3LBI6K879zENeoSOyn713lIU5hMSU4jhX06iT152PUqAiyrMbJFHKp9KI2JlZs0T90vB5JYYo9V_Lqe3n3Ad3sn5Yi7bBZJipHEsSavHYRQqEbvANdWFWDuU_7aClNbWeQrCPhbMdS3x5RVmBzRVYin-YXQVyBcp5FXhKQ'
								}
							}
						]
					},
					complianceCredential: {
						'@context': [
							'https://www.w3.org/2018/credentials/v1',
							'https://w3id.org/security/suites/jws-2020/v1',
							'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#'
						],
						type: ['VerifiableCredential'],
						id: 'https://compliance.lab.gaia-x.eu/development/credential-offers/18796976-180e-4093-ad4f-7109df1c843a',
						issuer: 'did:web:compliance.lab.gaia-x.eu:development',
						issuanceDate: '2023-07-31T11:47:40.929Z',
						expirationDate: '2023-10-29T11:47:40.929Z',
						credentialSubject: [
							{
								type: 'gx:compliance',
								id: 'https://greenworld.proofsense.in/.well-known/participant.json#0',
								integrity: 'sha256-e90774858dc28e973b67d4a9f556e74b34304f748e6c31b6ea6eaa65b02bf4d4',
								version: '22.10'
							},
							{
								type: 'gx:compliance',
								id: 'https://greenworld.proofsense.in/.well-known/participant.json#1',
								integrity: 'sha256-18f7c8532b1f1dcb3ed55447ff3a52e967cb37c7ccc3b108e033804954fc25f1',
								version: '22.10'
							},
							{
								type: 'gx:compliance',
								id: 'https://greenworld.proofsense.in/.well-known/participant.json#2',
								integrity: 'sha256-76abc0e83542bda3d76f5306f5635a22a5c21df440b62bbafa2eb3453599dfe4',
								version: '22.10'
							}
						],
						proof: {
							type: 'JsonWebSignature2020',
							created: '2023-07-31T11:47:41.567Z',
							proofPurpose: 'assertionMethod',
							jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..gCYEQBJ8DQlwoOVs-7kQ-KjQPkJxw8ns_GXKaRD-1ucnFjYb2PrDk60Mw4E3Qw5igog5oIpKmx6pHdeSnY-5Rs7NEgDVH4mhEq3KELeSn0hSz9uql2dLBMelthqAVPigeC9JhEO2j0a2UA6OFw6m5M7BCYA3IZANOf9TWqcuXRtQNBPTOK7vVIRbZx8VH8QTMGYxgniq3SqR6NTkFzFn8CwKL_iCW76tw4brRkWR0YtB_5BqNNUqCXAsdCO0SjPFCSJwWOPZgJbdRvxNjtZNJS9frAeMJHM2yit_fOIAqOW1GE3XP5ilqMOmdjyuUYd3X9V0ZhoUJotUVnepSnrPtg',
							verificationMethod: 'did:web:compliance.lab.gaia-x.eu:development'
						}
					}
				}
				//check if VC not null or in other form
				if (!participantJson?.selfDescriptionCredential?.verifiableCredential) {
					console.log(`❌ No Verifiable Credential Found`)
					res.status(400).json({
						error: `VC not found`,
						message: AppMessages.PARTICIPANT_VC_FOUND_FAILED
					})
					return
				} else if (!Array.isArray(participantJson.selfDescriptionCredential.verifiableCredential)) {
					console.log(`❌ Verifiable Credential isn't array`)
					res.status(400).json({
						error: `VC not valid`,
						message: AppMessages.PARTICIPANT_VC_INVALID
					})
					return
				}

				// check if complianceCred not null
				if (!participantJson?.complianceCredential || !participantJson?.complianceCredential?.proof) {
					console.log(`❌ Compliance Credential Not Found`)
					res.status(400).json({
						error: `Compliance Credential not found`,
						message: AppMessages.COMPLIANCE_CRED_FOUND_FAILED
					})
					return
				}

				// check VC are of valid type
				const { verifiableCredential, type } = participantJson.selfDescriptionCredential
				if (type[0] != 'VerifiableCredential' && type[0] != 'VerifiablePresentation') {
					console.log(`❌ Credential Type not supported`)
					res.status(400).json({
						error: `Credential Type not supported`
					})
					return
				}
				//fetching VC with subject type gx:LegalParticipant
				const VC = verifiableCredential?.find(async (vc: VerifiableCredentialDto) => {
					return vc?.credentialSubject?.type === 'gx:LegalParticipant'
				})
				if (!VC) {
					console.log(`❌ Verifiable Credential doesn't have type 'gx:LegalParticipant'`)
					res.status(400).json({
						error: `VC with type 'gx:LegalParticipant' not found!!`
					})
					return
				}
				for (const policy of policies) {
					console.log(`Executing ${policy} check ...`)
					switch (policy) {
						case AppConst.VERIFY_LP_POLICIES[0]: {
							// integrity check
							let allChecksPassed = true

							for (const vc of participantJson.selfDescriptionCredential.verifiableCredential) {
								const integrityHash = `sha256-${createHash('sha256').update(JSON.stringify(vc)).digest('hex')}`
								const credIntegrityHash = participantJson.complianceCredential?.credentialSubject?.find((cs: ComplianceCredential) => cs.id == vc.credentialSubject.id)?.integrity
								const integrityCheck = integrityHash === credIntegrityHash

								if (!integrityCheck) {
									allChecksPassed = false
									console.log(`❌ Integrity Failed`)
									break
								}
							}
							verificationStatus.integrityCheck = allChecksPassed
							break
						}

						case AppConst.VERIFY_LP_POLICIES[1]: {
							//holder sig verification
							const vcProof = VC.proof
							const vcCredentialContent = VC
							delete vcCredentialContent.proof
							verificationStatus.holderSignature = await verification(vcCredentialContent, vcProof, true)
							break
						}
						case AppConst.VERIFY_LP_POLICIES[2]: {
							// compliance sig verification
							const complianceCred = participantJson.complianceCredential
							const complianceProof = complianceCred.proof
							delete complianceCred.proof
							verificationStatus.complianceSignature = await verification(complianceCred, complianceProof, false)
							break
						}
						case AppConst.VERIFY_LP_POLICIES[3]: {
							verificationStatus.complianceCheck = true
							break
						}
					}
				}

				let validity = true

				for (const status in verificationStatus) {
					if (status !== 'valid' && !verificationStatus[status as keyof typeof verificationStatus]) {
						validity = false
						break
					}
				}

				verificationStatus.valid = validity
				res.status(200).json({
					data: { ...verificationStatus },
					message: 'verification successful'
				})
			}
		} catch (error) {
			res.status(500).json({
				error: (error as Error).message,
				message: AppMessages.SIG_VERIFY_FAILED
			})
		}
	}
)

/**
 * @dev takes the credential and proof, and verifies the signature is valid or not
 * @param credentialContent the credential part which will be hashed for proof
 * @param proof the proof obj
 * @returns boolean - true if the signature is verified
 */
const verification = async (credentialContent: VerifiableCredentialDto, proof: SignatureDto, checkSSLwithRegistry: boolean) => {
	// eslint-disable-next-line no-useless-catch
	try {
		// check if proof is of type JsonWebSignature2020
		if (proof.type !== 'JsonWebSignature2020') {
			console.log(`❌ signature type: '${proof.type}' not supported`)
			throw new Error(`signature type: '${proof.type}' not supported`)
		}

		// get the DID Document
		const ddo = await Utils.getDDOfromDID(proof.verificationMethod, resolver)
		if (!ddo) {
			console.log(`❌ DDO not found for given did: '${proof.verificationMethod}' in proof`)
			throw new Error(`DDO not found for given did: '${proof.verificationMethod}' in proof`)
		}

		// get the public keys from the DID Document
		// eslint-disable-next-line no-unsafe-optional-chaining
		const { publicKeyJwk } = ddo?.didDocument?.verificationMethod?.find((verMethod: VerificationMethod) => {
			if (verMethod.controller == proof.verificationMethod) {
				return verMethod
			}
		})
		if (!publicKeyJwk) {
			throw new Error('publicKeyJwk not found in ddo')
		}
		const x5u = publicKeyJwk.x5u
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
			const registryRes = await Utils.validateSslFromRegistryWithUri(x5u, axios)
			if (!registryRes) {
				throw new Error('Certificate validation failed')
			}
		}

		//check weather the public key from DDO(which is fetched from did) matches with the certificates of x5u(fetched from ddo)
		const comparePubKey = await Utils.comparePubKeys(certificates, publicKeyJwk, jose)
		if (!comparePubKey) {
			console.log(`❌ Public Keys Mismatched`)
			throw new Error('Public Key Mismatched')
		}

		// // normalize/canonize the credentialContent
		const canonizedCredential = await Utils.normalize(
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
		const hash = await Utils.sha256(crypto, canonizedCredential)

		// verify Signature by retrieving the hash and then comparing it
		const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
		console.log(verificationResult ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)
		return verificationResult
	} catch (error) {
		throw error
	}
}
