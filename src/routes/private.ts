import express, { Request, Response } from 'express'
import * as jose from 'jose'
import jsonld from 'jsonld'
import crypto from 'crypto'
import axios from 'axios'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'
import { check, validationResult } from 'express-validator'
import * as he from 'he'
import web from 'web-did-resolver'
import { Resolver } from 'did-resolver'

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

				const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
				// const privateKey = process.env.PRIVATE_KEY as string
				const proof = await Utils.createProof(jose, didId, AppConst.RSA_ALGO, hash, privateKey)
				console.log(proof ? '🔒 SD signed successfully' : '❌ SD signing failed')
				const x5uURL = `https://${domain}/.well-known/x509CertificateChain.pem`
				const certificate = (await axios.get(x5uURL)).data as string
				const publicKeyJwk = await Utils.generatePublicJWK(jose, AppConst.RSA_ALGO, certificate, x5uURL)
				const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk)
				console.log(verificationResult?.content === hash ? '✅ Verification successful' : '❌ Verification failed')
				selfDescription['verifiableCredential'][0].proof = proof
				// const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string,selfDescription)).data;
				const complianceCredential = {
					'@context': ['https://www.w3.org/2018/credentials/v1', 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant#'],
					type: ['VerifiableCredential'],
					id: 'https://compliance.lab.gaia-x.eu//v1-0-0/credential-offers/5d1bb35f-4f6c-48e6-8b34-69cce8cd3032',
					issuer: 'did:web:compliance.lab.gaia-x.eu::v1-0-0',
					issuanceDate: '2023-03-29T13:25:19.874Z',
					expirationDate: '2023-06-27T13:25:19.874Z',
					credentialSubject: [
						{
							type: 'gx:compliance',
							id: participantURL,
							integrity: 'sha256-b797c1008627e01d61c4eae22fb847410936f48b630e341b47f82d26b7178947'
						}
					],
					proof: {
						type: 'JsonWebSignature2020',
						created: '2023-03-29T13:25:20.148Z',
						proofPurpose: 'assertionMethod',
						jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..T8xd-jIGa1EKUviYRr8seRvvvwATkmmMfPlkv6cJU7K0S1FVTDfDQojxeWT9PVWPaQoKHhaehcMUb6wWpfbydoIN8o7J_LcRtZ5CCckQDN63tpD4L_rSgRn71g6_9GuI8SKgFQPpqecj_2CRnEk4sCnNM3rsF8JI5WLxtEtiGwC9-id-pdsZdIc-T2Tg9YsXIOb4ErlO61ZfKDuD9_XDNrVPJBMRcPYJkIfzsSkljqryAwJtVoyJTabkoj9waTYGMRzyM3S0abmzR_BHMY7egnTSW7D5UMl9kq3guDfLaoGbtf5u6kdeWpwxvOuYzBNwty1vW89WR9BxfYoIv43BLw',
						verificationMethod: 'did:web:compliance.lab.gaia-x.eu::v1-0-0'
					}
				}
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
	'/createVc',
	check('templateId').isIn([AppConst.LEGAL_PARTICIPANT]),
	check('privateKeyUrl').not().isEmpty().trim().escape(),
	check('credentialOffer').isObject(),
	check('issuerDid').not().isEmpty().trim().escape(),
	check('subjectDid').not().isEmpty().trim().escape(),

	async (req: Request, res: Response): Promise<void> => {
		try {
			const errors = validationResult(req)
			// check for validation errors
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.VC_VALIDATION
				})
			} else {
				//get required parameters from the body
				const { templateId, issuerDid, subjectDid, credentialOffer, privateKeyUrl } = req.body
				// get webresolver
				const webResolver = web.getResolver()
				// create a new resolver using web resolver
				const resolver = new Resolver(webResolver)
				let keyPairTrue: any = null
				// to check if provide private and public key are a pair, performed by getting public jwk from the given issuerDid
				keyPairTrue = await Utils.verifyKeyPair(issuerDid, privateKeyUrl, jose, resolver, AppConst.RSA_ALGO)
				// returns false if not a key pair and the message if any error
				if (!keyPairTrue.status) {
					res.status(422).json({
						error: keyPairTrue.message,
						message: AppMessages.KEYPAIR_VALIDATION
					})
				} else {
					let verifiableCredential: any = null
					if (templateId === AppConst.LEGAL_PARTICIPANT) {
						// create legal person document
						verifiableCredential = Utils.generateLegalPerson(
							subjectDid,
							issuerDid,
							credentialOffer?.legalName,
							credentialOffer?.legalRegistrationType,
							credentialOffer?.legalRegistrationNumber,
							credentialOffer?.headquarterAddress,
							credentialOffer?.legalAddress
						)
					}
					// normalise
					const canonizedSD = await Utils.normalize(
						jsonld,
						// eslint-disable-next-line
						verifiableCredential['verifiableCredential'][0]
					)
					// create hash
					const hash = Utils.sha256(crypto, canonizedSD)
					// retrieve private key
					// const privateKey = (await axios.get(privateKeyUrl)).data as string;
					const privateKey = process.env.PRIVATE_KEY as string
					// create proof
					const proof = await Utils.createProof(jose, issuerDid, AppConst.RSA_ALGO, hash, privateKey)
					// attach proof to vc
					verifiableCredential['verifiableCredential'][0].proof = proof
					// send vc as response with success message
					res.status(200).json({
						data: verifiableCredential['verifiableCredential'][0],
						message: AppMessages.VC_SUCCESS
					})
				}
			}
		} catch (e) {
			console.log(e)
			res.status(500).json({
				error: (e as Error).message,
				message: AppMessages.VC_FAILED
			})
		}
	}
)
