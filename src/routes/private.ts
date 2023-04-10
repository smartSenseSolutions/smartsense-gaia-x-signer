import express, { Request, Response } from 'express'
import * as jose from 'jose'
import jsonld from 'jsonld'
import crypto from 'crypto'
import axios from 'axios'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'
import { check, validationResult } from 'express-validator'
export const privateRoute = express.Router()

privateRoute.post(
	'/createWebDID',
	check('domain')
		.not()
		.isEmpty()
		.trim()
		.escape()
		.matches(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} of param '${errorsArr[0].param}'`,
					message: AppMessages.DID_VALIDATION
				})
			} else {
				const { domain } = req.body
				const didId = `did:web:${domain}`
				const x5uURL = `https://${domain}/.well-known/x509CertificateChain.pem`
				const certificate = (await axios.get(x5uURL)).data as string
				const publicKeyJwk = await Utils.generatePublicJWK(jose, AppConst.RSA_ALGO, certificate, x5uURL)
				const did = Utils.generateDID(didId, publicKeyJwk)
				res.status(200).json({
					data: { did },
					message: AppMessages.DID_SUCCESS
				})
			}
		} catch (e) {
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.DID_FAILED
			})
		}
	}
)

privateRoute.post(
	'/onBoardToGaiaX',
	check('domain')
		.not()
		.isEmpty()
		.trim()
		.escape()
		.matches(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/),
	check('templateId').isIn([AppConst.LEGAL_PARTICIPANT, AppConst.SERVICE_OFFER]),
	check('privateKeyUrl').not().isEmpty().trim().escape(),
	check('data').isObject(),
	check('data.legalName').not().isEmpty().trim().escape(),
	check('data.legalRegistrationType').not().isEmpty().trim().escape(),
	check('data.legalRegistrationNumber').not().isEmpty().trim().escape(),
	check('data.headquarterAddress').not().isEmpty().trim().escape(),
	check('data.legalAddress').not().isEmpty().trim().escape(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.VP_VALIDATION
				})
			} else {
				const { domain, templateId, privateKeyUrl } = req.body

				const didId = `did:web:${domain}`
				const participantURL = `https://${domain}/.well-known/participant.json`
				let selfDescription: any = null
				if (templateId === AppConst.LEGAL_PARTICIPANT) {
					const { legalName, legalRegistrationType, legalRegistrationNumber, headquarterAddress, legalAddress } = req.body.data
					selfDescription = Utils.generateLegalPerson(participantURL, didId, legalName, legalRegistrationType, legalRegistrationNumber, headquarterAddress, legalAddress)
				} else {
					res.status(422).json({
						error: `Type Not Supported`,
						message: AppMessages.DID_VALIDATION
					})
				}
				const canonizedSD = await Utils.normalize(
					jsonld,
					// eslint-disable-next-line
					selfDescription['verifiableCredential'][0]
				)
				const hash = Utils.sha256(crypto, canonizedSD)
				console.log(`📈 Hashed canonized SD ${hash}`)
				// const privateKey = (await axios.get(privateKeyUrl)).data as string;
				const privateKey = process.env.PRIVATE_KEY as string
				const proof = await Utils.createProof(jose, didId, AppConst.RSA_ALGO, hash, privateKey)
				console.log(proof ? '🔒 SD signed successfully' : '❌ SD signing failed')
				const x5uURL = `https://${domain}/.well-known/x509CertificateChain.pem`
				const certificate = (await axios.get(x5uURL)).data as string
				const publicKeyJwk = await Utils.generatePublicJWK(jose, AppConst.RSA_ALGO, certificate, x5uURL)
				const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk)
				console.log(verificationResult?.content === hash ? '✅ Verification successful' : '❌ Verification failed')
				selfDescription['verifiableCredential'][0].proof = proof
				// const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string,selfDescription)).data;
				const complianceCredential = {}
				console.log(complianceCredential ? '🔒 SD signed successfully (compliance service)' : '❌ SD signing failed (compliance service)')
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
			console.log(e)
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.VP_FAILED
			})
		}
	}
)

privateRoute.post(
	'/createVP',
	// check params
	check('claims').isArray(),
	check('templateId').isIn([AppConst.LEGAL_PARTICIPANT, AppConst.SERVICE_OFFER]),
	check('privateKeyUrl').not().isEmpty().trim().escape(),
	check('holderDID').exists().isString().trim(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.VP_VALIDATION
				})
			} else {
				const { templateId } = req.body

				let generatedVp: any = null
				if (templateId === AppConst.LEGAL_PARTICIPANT) {
					const { claims } = req.body
					generatedVp = Utils.createLpVpObj(claims)
				} else {
					res.status(422).json({
						error: `Type Not Supported`,
						message: AppMessages.VP_TYPE_NOT_SUPPORTED
					})
				}

				const { privateKeyUrl, holderDID } = req.body

				const canonizedCredential = await Utils.normalize(
					jsonld,
					// eslint-disable-next-line
					generatedVp.verifiableCredential[0]
				)
				if (typeof canonizedCredential === 'undefined') {
					throw new Error('canonizing failed')
				}

				const hash = await Utils.sha256(crypto, canonizedCredential)
				// const privateKey = (await axios.get(privateKeyUrl)).data as string;
				const privateKey = process.env.PRIVATE_KEY as string
				const proof = await Utils.createProof(jose, holderDID, AppConst.RSA_ALGO, hash, privateKey)
				console.log(proof ? '🔒 VP signed successfully' : '❌ VP signing failed')

				// Validate SHACL
				// Verify Signature

				generatedVp.verifiableCredential[0].proof = proof
				res.status(200).json({
					data: { verifiablePresentation: generatedVp },
					message: AppMessages.VP_SUCCESS
				})
			}
		} catch (e) {
			console.log(e)
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.VP_FAILED
			})
		}
	}
)
