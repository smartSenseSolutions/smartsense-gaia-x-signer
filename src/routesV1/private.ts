import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'
import axios from 'axios'
import crypto from 'crypto'
import { Resolver } from 'did-resolver'
import express, { Request, Response } from 'express'
import { check, validationResult } from 'express-validator'
import * as jose from 'jose'
import jsonld from 'jsonld'
import web from 'web-did-resolver'

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
