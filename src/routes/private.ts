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
import typer from 'media-typer'
import { createHash } from 'crypto'
// import { PublisherService } from '../utils/service/publisher.service'

export const privateRoute = express.Router()

const webResolver = web.getResolver()
const resolver = new Resolver(webResolver)
// const publisherService = new PublisherService()

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
			const { domain, tenant, services } = req.body
			if (services) {
				await check('services').isArray().run(req)
				for (let index = 0; index < services.length; index++) {
					await check(`services[${index}].type`).not().isEmpty().trim().escape().run(req)
					await check(`services[${index}].serviceEndpoint`).isURL().run(req)
				}
			}
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} of param '${errorsArr[0].param}'`,
					message: AppMessages.DID_VALIDATION
				})
			} else {
				const didId = tenant ? `did:web:${domain}:${tenant}` : `did:web:${domain}`
				const x5uURL = tenant ? `https://${domain}/${tenant}/x509CertificateChain.pem` : `https://${domain}/.well-known/x509CertificateChain.pem`
				const certificate = (await axios.get(x5uURL)).data as string
				const publicKeyJwk = await Utils.generatePublicJWK(jose, AppConst.RSA_ALGO, certificate, x5uURL)
				const did = Utils.generateDID(didId, publicKeyJwk, services)
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
	check('templateId').not().isEmpty().trim().escape().isIn([AppConst.LEGAL_PARTICIPANT, AppConst.SERVICE_OFFER]),
	check('privateKeyUrl').not().isEmpty().trim().escape(),
	check('data').isObject(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const { domain, tenant, templateId, privateKeyUrl } = req.body
			if (templateId === AppConst.LEGAL_PARTICIPANT) {
				await check('data.legalName').not().isEmpty().trim().escape().run(req)
				await check('data.legalRegistrationType').not().isEmpty().trim().escape().run(req)
				await check('data.legalRegistrationNumber').not().isEmpty().trim().escape().run(req)
				await check('data.headquarterAddress').not().isEmpty().trim().escape().run(req)
				await check('data.legalAddress').not().isEmpty().trim().escape().run(req)
			} else if (templateId === AppConst.SERVICE_OFFER) {
				await check('data.name').not().isEmpty().trim().escape().run(req)
				await check('data.description').not().isEmpty().trim().escape().run(req)
				await check('data.fileName').not().isEmpty().trim().escape().run(req)
				await check('data.policyUrl').not().isEmpty().trim().escape().run(req)
				await check('data.termsAndConditionsUrl').not().isEmpty().trim().escape().run(req)
				await check('data.termsAndConditionsHash').not().isEmpty().trim().escape().run(req)
				await check('data.formatType')
					.not()
					.isEmpty()
					.trim()
					.escape()
					.custom((val) => typer.test(he.decode(val)))
					.run(req)
				await check('data.accessType').not().isEmpty().trim().escape().isIn(AppConst.ACCESS_TYPES).run(req)
				await check('data.requestType').not().isEmpty().trim().escape().isIn(AppConst.REQUEST_TYPES).run(req)
			}
			const errors = validationResult(req)
			if (!errors.isEmpty()) {
				const errorsArr = errors.array()
				res.status(422).json({
					error: `${errorsArr[0].msg} for param '${errorsArr[0].param}'`,
					message: AppMessages.VP_VALIDATION
				})
			} else {
				const didId = tenant ? `did:web:${domain}:${tenant}` : `did:web:${domain}`
				const participantURL = tenant ? `https://${domain}/${tenant}/participant.json` : `https://${domain}/.well-known/participant.json`
				let selfDescription: any = null
				if (templateId === AppConst.LEGAL_PARTICIPANT) {
					const { legalName, legalRegistrationType, legalRegistrationNumber, headquarterAddress, legalAddress } = req.body.data
					selfDescription = Utils.generateLegalPerson(participantURL, didId, legalName, legalRegistrationType, legalRegistrationNumber, headquarterAddress, legalAddress)
				} else if (templateId === AppConst.SERVICE_OFFER) {
					const data = JSON.parse(he.decode(JSON.stringify(req.body.data)))
					const serviceComplianceUrl = tenant ? `https://${domain}/${tenant}/${data.fileName}` : `https://${domain}/.well-known/${data.fileName}`
					selfDescription = Utils.generateServiceOffer(participantURL, didId, serviceComplianceUrl, data)
					const { selfDescriptionCredential } = (await axios.get(participantURL)).data
					selfDescription.verifiableCredential.push(selfDescriptionCredential.verifiableCredential[0])
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
				const x5uURL = tenant ? `https://${domain}/${tenant}/x509CertificateChain.pem` : `https://${domain}/.well-known/x509CertificateChain.pem`
				const certificate = (await axios.get(x5uURL)).data as string
				const publicKeyJwk = await Utils.generatePublicJWK(jose, AppConst.RSA_ALGO, certificate, x5uURL)

				const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
				console.log(verificationResult ? '✅ Verification successful' : '❌ Verification failed')

				selfDescription['verifiableCredential'][0].proof = proof
				const complianceCredential = (await axios.post(process.env.COMPLIANCE_SERVICE as string, selfDescription)).data
				// const complianceCredential = {}
				console.log(complianceCredential ? '🔒 SD signed successfully (compliance service)' : '❌ SD signing failed (compliance service)')
				// await publisherService.publishVP(complianceCredential);
				const completeSd = {
					selfDescriptionCredential: selfDescription,
					complianceCredential: complianceCredential
				}

				res.status(200).json({
					data: { verifiableCredential: completeSd },
					message: AppMessages.VP_SUCCESS
				})
			}
		} catch (error: any) {
			if (error.response) {
				// The request was made and the server responded with a status code
				// that falls out of the range of 2xx
				console.log(error.response.data)
				console.log(error.response.status)
				console.log(error.response.headers)
			} else if (error.request) {
				// The request was made but no response was received
				// `error.request` is an instance of XMLHttpRequest in the browser and an instance of
				// http.ClientRequest in node.js
				console.log(error.request)
			} else {
				// Something happened in setting up the request that triggered an Error
				console.log('Error', error.message)
			}
			res.status(500).json({
				error: (error as Error).message,
				message: AppMessages.VP_FAILED
			})
		}
	}
)

privateRoute.post(
	'/createVC',
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
				const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
				// const privateKey = process.env.PRIVATE_KEY as string
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

				for (const claim of claims) {
					let proof, credentialContent
					if (claim.type.includes('VerifiableCredential')) {
						proof = claim.proof
						credentialContent = JSON.parse(JSON.stringify(claim))
						delete credentialContent.proof
						console.log('Verifying a Verifiable Credential claim ...')
					} else if (claim.type.includes('VerifiablePresentation')) {
						console.log(`❌ Cannot include VP as a claim inside of VP`)
						res.status(400).json({
							error: `Invalid VP structure | Cannot include VP as a claim inside of VP`
						})
						return
					} else {
						console.log(`❌ Credential Type in claim not supported`)
						res.status(400).json({
							error: `Credential Type not supported`
						})
						return
					}
					try {
						await verification(credentialContent, proof, res, AppConst.checkSSLwithRegistry)
					} catch (error) {
						res.status(422).json({
							error: 'Signature verification of provided claim failed',
							message: AppMessages.CLAIM_SIG_VERIFY_FAILED
						})
						return
					}
				}
				const generatedVp: any = Utils.createVpObj(claims)
				const canonizedCredential = await Utils.normalize(
					jsonld,
					// eslint-disable-next-line
					generatedVp
				)
				if (typeof canonizedCredential === 'undefined') {
					throw new Error('canonizing failed')
				}

				const hash = await Utils.sha256(crypto, canonizedCredential)
				const privateKey = (await axios.get(he.decode(privateKeyUrl))).data as string
				// const privateKey = process.env.PRIVATE_KEY as string
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
	'/verify',
	check('policies')
		.isArray()
		.exists()
		.custom((obj) => {
			for (const policy of obj) {
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

				// Check if the credential is of type VerifiableCredential or VerifiablePresentation, and seperate credentialContent and proof accordingly
				let credentialContent, proof
				if (credential.type.includes('VerifiableCredential')) {
					proof = credential.proof
					delete credential.proof
					credentialContent = credential
					console.log('Verifying a Verifiable Credential...')
				} else if (credential.type.includes('VerifiablePresentation')) {
					proof = credential.proof
					delete credential.proof
					credentialContent = credential
					console.log('Verifying a Verifiable Presentation...')
				} else {
					console.log(`❌ Credential Type not supported`)
					res.status(400).json({
						error: `Credential Type not supported`
					})
					return
				}

				const responseObj: any = {}
				// execute functions based on the policies To Execute and add the result to responseObj
				for (const policy of policies) {
					switch (policy) {
						case AppConst.VERIFY_POLICIES[0]: //checkSignature
							console.log(`Executing ${policy} policy...`)
							responseObj.checkSignature = await verification(credentialContent, proof, res, AppConst.checkSSLwithRegistry)
							if (typeof responseObj.checkSignature !== 'boolean') return
							break

						case AppConst.VERIFY_POLICIES[1]: //gx-Compliance
							console.log(`Executing ${policy} policy...`)
							let gxComplianceCheck = await verifyGxCompliance(credentialContent, res)
							responseObj.gxCompliance = gxComplianceCheck
							if (typeof responseObj.gxCompliance !== 'boolean') return
							break

						default:
							break
					}
				}
				if (credential.type.includes('VerifiablePresentation')) {
					for (const claim of credential.verifiableCredential) {
						if (claim.type.includes('VerifiableCredential')) {
							proof = claim.proof
							delete claim.proof
							credentialContent = claim
							console.log('Verifying a Verifiable Credential claim...')
						} else if (claim.type.includes('VerifiablePresentation')) {
							console.log(`❌ Invalid VP structure`)
							res.status(400).json({
								error: `Invalid VP structure`
							})
							return
						} else {
							console.log(`❌ Claim Credential Type not supported`)
							res.status(400).json({
								error: `Credential Type not supported`
							})
							return
						}
						try {
							await verification(credentialContent, proof, res, AppConst.checkSSLwithRegistry)
						} catch (error) {
							res.status(400).json({
								error: (error as Error).message,
								message: AppMessages.CLAIM_SIG_VERIFY_FAILED
							})
							return
						}
					}
				}
				res.status(200).json({
					data: responseObj,
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

/**
 * @dev takes the credential and proof, and verifies the signature is valid or not
 * @param credentialContent the credential part which will be hashed for proof
 * @param proof the proof obj
 * @param res express response obj
 * @param checkSSLwithRegistry perform ssl validation with gaiax registry or not
 * @returns boolean - true if the signature is verified
 */
async function verification(credentialContent: any, proof: any, res: Response, checkSSLwithRegistry: boolean = false) {
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
	if (!ddo.didDocument.verificationMethod[0].publicKeyJwk || !ddo.didDocument.verificationMethod[0].publicKeyJwk.x5u) {
		res.status(400).json({
			error: `Compliance credential structure invalid`
		})
		return
	}
	const publicKeyJwk = ddo.didDocument.verificationMethod[0].publicKeyJwk
	const x5u = ddo.didDocument.verificationMethod[0].publicKeyJwk.x5u
	let certificates
	// get the SSL certificates from x5u url
	try {
		certificates = (await axios.get(x5u)).data as string
	} catch (e) {
		console.log(`❌ Couldn't fetch x5u certificate`)
		res.status(400).json({
			error: `Couldn't fetch x5u certificate`,
			message: AppMessages.X5U_FETCH_FAILED
		})
		return
	}
	if (!certificates.includes('-----BEGIN CERTIFICATE-----') || !certificates.includes('-----END CERTIFICATE-----')) {
		console.log(`❌ x5u certificate invalid`)

		res.status(400).json({
			error: `x5u certificate invalid`,
			message: AppMessages.X5U_VALIDATION_FAILED
		})
		return
	}
	if (checkSSLwithRegistry) {
		// signature check against Gaia-x registry
		const registryRes = await Utils.validateSslFromRegistry(certificates, axios)
		if (!registryRes) {
			console.log(`❌ Certificates validation Failed`)
			res.status(400).json({
				error: `Certificates validation Failed`,
				message: AppMessages.CERT_VALIDATION_FAILED
			})
			return
		}
	}

	//check weather the public key from DDO(which is fetched from did) matches with the certificates of x5u(fetched from ddo)
	const comparePubKey = await Utils.comparePubKeys(certificates, publicKeyJwk, jose)
	if (!comparePubKey) {
		console.log(`❌ Public Keys Mismatched`)
		res.status(400).json({
			error: `Public Keys Mismatched`,
			message: AppMessages.PUB_KEY_MISMATCH
		})
		return
	}

	// normalize/canonize the credentialContent
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

	// verify Signature by retriving the hash and then comparing it
	const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
	console.log(verificationResult ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)
	return verificationResult
}

/**
 * @dev Verify if a given credentialContent is compliant with GX standards, and if it's signature is valid.
 * @param {any} credentialContent - The content of the credential to be verified.
 * @param {Response} res - The Response object of the request.
 * @returns {boolean} - Validation status
 */
async function verifyGxCompliance(credentialContent: any, res: Response) {
	let url
	// get id from compliance credential
	if (credentialContent.type.includes('VerifiablePresentation')) {
		if (!credentialContent.verifiableCredential[0].credentialSubject.id) {
			console.log(`❌ Verifiable Presentation invalid structure`)

			res.status(400).json({
				error: `Verifiable Presentation invalid structure`
			})
			return
		}
		url = credentialContent.verifiableCredential[0].credentialSubject.id
	} else {
		if (!credentialContent.credentialSubject.id) {
			console.log(`❌ Verifiable Credential invalid structure`)
			res.status(400).json({
				error: `Verifiable Credential invalid structure`
			})
			return
		}
		url = credentialContent.credentialSubject.id
	}
	let participantJson
	// fetch compliance credential from the id
	try {
		participantJson = await axios.get(url)
	} catch (e) {
		console.log(`❌ Invalid id in credential subject`)

		res.status(400).json({
			error: `Invalid id in credential subject`
		})
		return
	}
	// checking compliance credential has no missing values
	if (
		!participantJson.data.complianceCredential ||
		!participantJson.data.complianceCredential.proof ||
		!participantJson.data.selfDescriptionCredential.verifiableCredential[0] ||
		!participantJson.data.complianceCredential.credentialSubject[0].integrity
	) {
		console.log(`❌ Compliance Credential Structure Invalid`)

		res.status(400).json({
			error: `Compliance Credential Structure Invalid`
		})
		return
	}
	const compCred = participantJson.data.complianceCredential
	const gxProof = compCred.proof
	delete compCred.proof
	const gxCred = compCred

	// verify signature
	const signVerify = await verification(gxCred, gxProof, res)

	// verify integrity hash
	const vcToHash = participantJson.data.selfDescriptionCredential.verifiableCredential[0]
	const integrityHash = `sha256-${createHash('sha256').update(JSON.stringify(vcToHash)).digest('hex')}`

	// compare hashes
	const credIntegrityHash = participantJson.data.complianceCredential.credentialSubject[0].integrity
	const integrityCheck = integrityHash === credIntegrityHash

	return signVerify && integrityCheck
}
