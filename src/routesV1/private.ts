import axios from 'axios'
import crypto, { createHash } from 'crypto'
import { Resolver } from 'did-resolver'
import express, { Request, Response } from 'express'
import { check, validationResult } from 'express-validator'
import * as jose from 'jose'
import jsonld from 'jsonld'
import web from 'web-did-resolver'

import { ComplianceCredential, SignatureDto, VerifiableCredentialDto, VerificationMethod, VerificationStatus } from '../interface/interface'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'

const webResolver = web.getResolver()
const resolver = new Resolver(webResolver)
export const privateRoute = express.Router()

privateRoute.post(
	'/gaia-x/legal-participant',
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
			const { legalParticipant, legalRegistrationNumber, gaiaXTermsAndConditions } = vcs
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
				const completeSD = {
					selfDescriptionCredential: selfDescription,
					complianceCredential: complianceCredential
				}

				res.status(200).json({
					data: completeSD,
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
	'/gaia-x/service-offering',
	check('privateKey').not().isEmpty().trim().escape(),
	check('issuer').not().isEmpty().trim().escape(),
	check('verificationMethod').not().isEmpty().trim().escape(),
	check('legalParticipantURL')
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
				legalParticipantURL,
				verificationMethod,
				issuer,
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
				const legalParticipant = (await axios.get(legalParticipantURL)).data
				// const legalParticipant = require('./../../legalParticipant.json')
				const {
					selfDescriptionCredential: { verifiableCredential }
				} = legalParticipant

				const ddo = await Utils.getDDOfromDID(issuer, resolver)
				if (!ddo) {
					console.error(`❌ DDO not found for given did: '${issuer}' in proof`)
					res.status(400).json({
						error: `DDO not found for given did: '${issuer}' in proof`
					})
					return
				}

				const { x5u } = await Utils.getPublicKeys(ddo.didDocument)
				privateKey = Buffer.from(privateKey, 'base64').toString('ascii')

				const proof = await Utils.addProof(jsonld, axios, jose, crypto, serviceOffering, privateKey, verificationMethod, AppConst.RSA_ALGO, x5u)
				serviceOffering.proof = proof
				verifiableCredential.push(serviceOffering)

				// Create VP for service offering
				const selfDescriptionCredential = Utils.createVP(verifiableCredential)

				// Call compliance service to sign in gaia-x
				const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string, selfDescriptionCredential)).data
				console.log(complianceCredential ? '🔒 SD signed successfully (compliance service)' : '❌ SD signing failed (compliance service)')

				const completeSD = {
					selfDescriptionCredential: selfDescriptionCredential,
					complianceCredential: complianceCredential
				}

				// Calculate Veracity
				const { veracity, certificateDetails } = await Utils.calcVeracity(verifiableCredential, resolver)
				console.log('🔒 veracity calculated')

				// Calculate Transparency
				const { credentialSubject } = serviceOffering
				const transparency: number = await Utils.calcTransparency(credentialSubject)
				console.log('🔒 transparency calculated')

				// Calculate TrustIndex
				const trustIndex: number = Utils.calcTrustIndex(veracity, transparency)
				console.log('🔒 trustIndex calculated')

				res.status(200).json({
					data: {
						completeSD,
						trustIndex: {
							veracity,
							transparency,
							trustIndex,
							certificateDetails
						}
					},
					message: AppMessages.SD_SIGN_SUCCESS
				})
			}
		} catch (error) {
			console.error(`❌ ${AppMessages.SD_SIGN_FAILED} :- error \n`, error)
			res.status(500).json({
				error: (error as Error).message,
				message: AppMessages.SD_SIGN_FAILED
			})
		}
	}
)

privateRoute.post(
	'/verify',
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
				const participantJson = await Utils.fetchParticipantJson(participantUrl)

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
				if (!Array.isArray(type) || !(type.includes('VerifiableCredential') || type.includes('VerifiablePresentation'))) {
					console.log(`❌ Credential Type not supported`)
					res.status(400).json({
						error: `Credential Type not supported`,
						message: `Credential Type not supported`
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
					message: AppMessages.SIG_VERIFY_SUCCESS
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
