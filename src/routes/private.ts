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

const webResolver = web.getResolver()
const resolver = new Resolver(webResolver)

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
				const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string, selfDescription)).data
				// const complianceCredential = {
				// 	'@context': ['https://www.w3.org/2018/credentials/v1', 'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/participant#'],
				// 	type: ['VerifiableCredential'],
				// 	id: 'https://compliance.lab.gaia-x.eu//v1-0-0/credential-offers/5d1bb35f-4f6c-48e6-8b34-69cce8cd3032',
				// 	issuer: 'did:web:compliance.lab.gaia-x.eu::v1-0-0',
				// 	issuanceDate: '2023-03-29T13:25:19.874Z',
				// 	expirationDate: '2023-06-27T13:25:19.874Z',
				// 	credentialSubject: [
				// 		{
				// 			type: 'gx:compliance',
				// 			id: participantURL,
				// 			integrity: 'sha256-b797c1008627e01d61c4eae22fb847410936f48b630e341b47f82d26b7178947'
				// 		}
				// 	],
				// 	proof: {
				// 		type: 'JsonWebSignature2020',
				// 		created: '2023-03-29T13:25:20.148Z',
				// 		proofPurpose: 'assertionMethod',
				// 		jws: 'eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..T8xd-jIGa1EKUviYRr8seRvvvwATkmmMfPlkv6cJU7K0S1FVTDfDQojxeWT9PVWPaQoKHhaehcMUb6wWpfbydoIN8o7J_LcRtZ5CCckQDN63tpD4L_rSgRn71g6_9GuI8SKgFQPpqecj_2CRnEk4sCnNM3rsF8JI5WLxtEtiGwC9-id-pdsZdIc-T2Tg9YsXIOb4ErlO61ZfKDuD9_XDNrVPJBMRcPYJkIfzsSkljqryAwJtVoyJTabkoj9waTYGMRzyM3S0abmzR_BHMY7egnTSW7D5UMl9kq3guDfLaoGbtf5u6kdeWpwxvOuYzBNwty1vW89WR9BxfYoIv43BLw',
				// 		verificationMethod: 'did:web:compliance.lab.gaia-x.eu::v1-0-0'
				// 	}
				// }
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
	'/createVC',
	check('templateId').isIn([AppConst.LEGAL_PARTICIPANT, AppConst.SERVICE_OFFER]),
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

				let keyPairTrue: any = null
				// to check if provide private and public key are a pair, performed by getting public jwk from the given issuerDid
				keyPairTrue = await Utils.verifyKeyPair(
					issuerDid,
					privateKeyUrl,
					jose,
					resolver,
					AppConst.RSA_ALGO,
					axios,
					he,
					AppConst.FLATTEN_ENCRYPT_ALGORITHM,
					AppConst.FLATTEN_ENCRYPT_ENCODING
				)
				// returns false if not a key pair and the message if any error
				if (!keyPairTrue.status) {
					res.status(422).json({
						error: keyPairTrue.message,
						message: AppMessages.KEYPAIR_VALIDATION
					})
				}

				let resCredential: any = null
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

					// normalise
					const canonizedSD = await Utils.normalize(
						jsonld,
						// eslint-disable-next-line
						verifiableCredential['verifiableCredential'][0]
					)
					// create hash
					const hash = Utils.sha256(crypto, canonizedSD)
					// retrieve private key
					// const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
					const privateKey = process.env.PRIVATE_KEY as string
					// create proof
					const proof = await Utils.createProof(jose, issuerDid, AppConst.RSA_ALGO, hash, privateKey)
					// attach proof to vc
					verifiableCredential['verifiableCredential'][0].proof = proof

					resCredential = verifiableCredential['verifiableCredential'][0]
				} else if (templateId === AppConst.SERVICE_OFFER) {
					verifiableCredential = Utils.generateServiceOffObj(
						subjectDid,
						issuerDid,
						credentialOffer?.name,
						credentialOffer?.producedBy,
						credentialOffer?.copyrightOwnedBy,
						credentialOffer?.description,
						credentialOffer?.license,
						credentialOffer?.policy,
						credentialOffer?.expiration,
						credentialOffer?.articleNumber,
						credentialOffer?.group,
						credentialOffer?.GTIN,
						credentialOffer?.image,
						credentialOffer?.model,
						credentialOffer?.KBAnumber,
						credentialOffer?.cradleToGat
					)

					const canonizedSD = await Utils.normalize(
						jsonld,
						// eslint-disable-next-line
						verifiableCredential
					)

					const hash = Utils.sha256(crypto, canonizedSD)
					// const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
					const privateKey = process.env.PRIVATE_KEY as string
					const proof = await Utils.createProof(jose, issuerDid, AppConst.RSA_ALGO, hash, privateKey)
					verifiableCredential.proof = proof

					resCredential = verifiableCredential
				}

				// send vc as response with success message
				res.status(200).json({
					data: resCredential,
					message: AppMessages.VC_SUCCESS
				})
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

privateRoute.post(
	'/createVP',
	// check params
	check('claims').isArray(),
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
				const { privateKeyUrl, holderDID, claims } = req.body

				// TODO - check the relation between holder DID and the provided claims

				const generatedVp: any = Utils.createVpObj(claims)
				const canonizedCredential = await Utils.normalize(
					jsonld,
					// eslint-disable-next-line
					generatedVp.verifiableCredential
				)
				if (typeof canonizedCredential === 'undefined') {
					throw new Error('canonizing failed')
				}

				const hash = await Utils.sha256(crypto, canonizedCredential)
				// const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
				const privateKey = process.env.PRIVATE_KEY as string
				const proof = await Utils.createProof(jose, holderDID, AppConst.RSA_ALGO, hash, privateKey)
				console.log(proof ? '🔒 VP signed successfully' : '❌ VP signing failed')

				generatedVp.proof = proof
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

privateRoute.post(
	'/verifySignature',
	check('policies')
		.isObject()
		.exists()
		.custom((obj) => {
			for (const policy in obj) {
				if (!AppConst.VERIFY_POLICIES.includes(policy)) {
					return false
				}
			}
			return true
		}),
	check('credential').isObject().exists(),
	check('credential.type').exists(),
	check('credential.proof').isObject().exists(),
	check('credential.proof.type').exists().isString(),
	check('credential.proof.verificationMethod').exists().isString(),
	check('credential.proof.jws').exists().isString(),

	async (req: Request, res: Response): Promise<void> => {
		try {
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} of param '${errorsArr[0].param}'`,
					message: AppMessages.SIG_VERIFY_VALIDATION
				})
			} else {
				const { credential, policies } = req.body

				let credentialContent, proof
				if (credential.type.includes('VerifiableCredential') && credential.type.includes('gx:LegalParticipant')) {
					proof = credential.proof
					delete credential.proof
					credentialContent = credential
					console.log('Verifying a gx:LegalParticipant Verifiable Credential...')
				} else if (credential.type.includes('VerifiablePresentation')) {
					credentialContent = credential.verifiableCredential
					proof = credential.proof
					console.log('Verifying a Verifiable Presentation...')
				} else {
					console.log(`❌ Credential Type not supported`)
					res.status(400).json({
						error: `Credential Type not supported`
					})
					return
				}

				// get the policies set to true from request
				const policyToExecute = Object.keys(policies).filter((key) => {
					return policies[key] === true
				})
				// check that policyToExecute is not empty
				if (policyToExecute.length === 0) {
					console.log(`❌ No policy to execute`)
					res.status(400).json({
						error: `No policy to execute`
					})
					return
				}

				const responseObj: any = {}
				for (const policy of policyToExecute) {
					switch (policy) {
						case AppConst.VERIFY_POLICIES[0]: //checkSignature
							console.log(`Executing ${policy} policy...`)
							responseObj.checkSignature = await verification(credentialContent, proof, res)
							if (typeof responseObj.checkSignature !== 'boolean') return
							break

						case AppConst.VERIFY_POLICIES[1]: //policy2
							console.log(`Executing ${policy} policy...`)
							// specific function call for policy
							responseObj.policy2 = true
							break

						default:
							break
					}
				}

				res.status(200).json({
					data: { responseObj },
					message: AppMessages.SIG_VERIFY_SUCCESS
				})
			}
		} catch (error) {
			console.log(error)
			res.status(500).json({
				error: (error as Error).message,
				message: AppMessages.SIG_VERIFY_FAILED
			})
		}
	}
)

async function verification(credentialContent: any, proof: any, res: Response) {
	if (proof.type !== 'JsonWebSignature2020') {
		console.log(`❌ signature type: '${proof.type}' not supported`)
		res.status(400).json({
			error: `signature type: '${proof.type}' not supported`,
			message: AppMessages.ONLY_JWS2020
		})
		return
	}

	const ddo = await Utils.getDDOfromDID(proof.verificationMethod, resolver)
	if (!ddo) {
		console.log(`❌ DDO not found for given did: '${proof.verificationMethod}' in proof`)
		res.status(400).json({
			error: `DDO not found for given did: '${proof.verificationMethod}' in proof`
		})
		return
	}

	const publicKeyJwk = ddo.didDocument.verificationMethod[0].publicKeyJwk
	const x5u = ddo.didDocument.verificationMethod[0].publicKeyJwk.x5u

	// get the SSL certificates
	const certificates = (await axios.get(x5u)).data as string

	// signature check against registry
	const registryRes = await Utils.validateSslFromRegistry(certificates, axios)
	if (!registryRes) {
		res.status(400).json({
			error: `Certificates validation Failed`,
			message: AppMessages.CERT_VALIDATION_FAILED
		})
		return
	}

	//check weather the public key matches with the certificate
	const comparePubKey = await Utils.comparePubKeys(certificates, publicKeyJwk, jose)
	if (!comparePubKey) {
		console.log(`❌ Public Keys Mismatched`)
		res.status(400).json({
			error: `Public Keys Mismatched`,
			message: AppMessages.PUB_KEY_MISMATCH
		})
		return
	}

	/**
	 * Signature Check Flow
	 */

	// normalize
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

	// hash
	const hash = await Utils.sha256(crypto, canonizedCredential)

	// verify Signature
	const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk)
	const isVerified = verificationResult?.content === hash
	console.log(isVerified ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)

	return isVerified
}
