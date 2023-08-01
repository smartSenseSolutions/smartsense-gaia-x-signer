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
import { VerifiableCredentialDto } from '../interface/interface'

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

privateRoute.post('/VerifyLegalParticipant', async (req: Request, res: Response): Promise<void> => {
	/* Request Body :
	 * 1. Participant URL : EG . https://greenworld.proofsense.in/.well-known/participant.json
	 */
	//todo : compliance check is remaining
	try {
		const { participantUrl } = req.body
		const verificationStatus = {
			holderSig: false,
			issuerSig: false,
			integritySig: false,
			complianceCheck: true,
			isLegalParticipant: false
		}

		console.log('fetching participant json...')
		const participantJson = await Utils.fetchParticipantJson(participantUrl)

		participantJson.selfDescriptionCredential.verifiableCredential.map((vc: any, index: number) => {
			const integrityHash = `sha256-${createHash('sha256').update(JSON.stringify(vc)).digest('hex')}`
			const credIntegrityHash = participantJson.complianceCredential.credentialSubject[index].integrity

			const integrityCheck = integrityHash === credIntegrityHash
			verificationStatus.integritySig = integrityCheck
		})

		const { verifiableCredential, type } = participantJson.selfDescriptionCredential
		if (type[0] != 'VerifiableCredential' && type[0] != 'VerifiablePresentation') {
			console.log(`❌ Credential Type not supported`)
			res.status(400).json({
				error: `Credential Type not supported`
			})
			return
		}

		//fetching VC with subject type gx:LegalParticipant
		const VC = verifiableCredential.find(async (vc: VerifiableCredentialDto) => {
			return vc.credentialSubject.type === 'gx:LegalParticipant'
		})

		if (!VC) {
			console.log(`❌ Verifiable Credential doesn't have type 'gx:LegalParticipant'`)
			res.status(400).json({
				error: `VC with type 'gx:LegalParticipant' not found!!`
			})
			return
		}
		const vcProof = VC.proof
		const vcCredentialContent = VC
		delete vcCredentialContent.proof
		console.log('Verifying Holder Signature...')
		const result = await verification(vcCredentialContent, vcProof, res, true)

		if (typeof result == 'undefined') {
			return
		} else {
			verificationStatus.holderSig = result
		}

		console.log('Verifying Issuer Signature...')

		const gxResult = await verifyGxCompliance(vcCredentialContent, res)

		if (typeof gxResult == 'undefined') {
			return
		} else {
			verificationStatus.issuerSig = gxResult
		}

		verificationStatus.isLegalParticipant = verificationStatus.integritySig && verificationStatus.holderSig && verificationStatus.issuerSig && verificationStatus.complianceCheck
		res.status(200).json({
			...verificationStatus
		})
	} catch (error) {
		console.log(error)
		res.status(500).json({
			error: (error as Error).message,
			message: AppMessages.SIG_VERIFY_FAILED
		})
	}
})

/**
 * @dev takes the credential and proof, and verifies the signature is valid or not
 * @param credentialContent the credential part which will be hashed for proof
 * @param proof the proof obj
 * @param res express response obj
 * @returns boolean - true if the signature is verified
 */
const verification = async (credentialContent: any, proof: any, res: Response, checkSSLwithRegistry: boolean) => {
	// check if proof is of type JsonWebSignature2020
	if (proof.type !== 'JsonWebSignature2020') {
		console.log(`❌ signature type: '${proof.type}' not supported`)
		res.status(400).json({
			error: `signature type: '${proof.type}' not supported`,
			message: AppMessages.ONLY_JWS2020
		})
		return
	}

	// get the DID Document
	const ddo = await Utils.getDDOfromDID(proof.verificationMethod, resolver)
	if (!ddo) {
		console.log(`❌ DDO not found for given did: '${proof.verificationMethod}' in proof`)
		res.status(400).json({
			error: `DDO not found for given did: '${proof.verificationMethod}' in proof`
		})
		return
	}

	// get the public keys from the DID Document
	const { publicKeyJwk } = ddo.didDocument.verificationMethod.find((verMethod: any) => {
		if (verMethod.controller == proof.verificationMethod) {
			return verMethod
		}
	})

	const x5u = publicKeyJwk.x5u

	// get the SSL certificates from x5u url
	const certificates = (await axios.get(x5u)).data as string

	if (checkSSLwithRegistry) {
		// signature check against Gaia-x registry
		const registryRes = await Utils.validateSslFromRegistryWithUri(x5u, axios)
		if (!registryRes) {
			res.status(400).json({
				error: `Certificates validation Failed`,
				message: AppMessages.CERT_VALIDATION_FAILED
			})
			return
		}
	}

	// //check weather the public key from DDO(which is fetched from did) matches with the certificates of x5u(fetched from ddo)
	const comparePubKey = await Utils.comparePubKeys(certificates, publicKeyJwk, jose)
	if (!comparePubKey) {
		console.log(`❌ Public Keys Mismatched`)
		res.status(400).json({
			error: `Public Keys Mismatched`,
			message: AppMessages.PUB_KEY_MISMATCH
		})
		return
	}

	// // normalize/canonize the credentialContent
	const canonizedCredential = await Utils.normalize(
		jsonld,
		// eslint-disable-next-line
		credentialContent
	)

	if (typeof canonizedCredential === 'undefined') {
		console.log(`❌ Normalizing Credential Failed`)
		res.status(400).json({
			error: `Normalizing Credential Failed`
		})
		return
	}

	// TODO: explore the isValidityCheck here, to include the jws in the hash

	// hash the normalized credential
	const hash = await Utils.sha256(crypto, canonizedCredential)

	// verify Signature by retrieving the hash and then comparing it

	const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
	console.log(verificationResult ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)
	return verificationResult
}

async function verifyGxCompliance(credentialContent: any, res: Response) {
	let url
	if (credentialContent.type.includes('VerifiablePresentation')) {
		url = credentialContent.credentialSubject.id
	} else {
		url = credentialContent.credentialSubject.id
	}
	const participantJson = await Utils.fetchParticipantJson(url)
	const compCred = participantJson.complianceCredential
	const gxProof = compCred.proof
	delete compCred.proof
	const gxCred = compCred

	const signVerify = await verification(gxCred, gxProof, res, false)

	return signVerify
}
