import axios from 'axios'
/* eslint-disable no-case-declarations */
import crypto, { X509Certificate } from 'crypto'
import { createHash } from 'crypto'
import { Resolver } from 'did-resolver'
import express, { Request, Response } from 'express'
import { check, validationResult } from 'express-validator'
import * as he from 'he'
import * as jose from 'jose'
import jsonld from 'jsonld'
import typer from 'media-typer'
import web from 'web-did-resolver'

import { X509CertificateDetail } from '../interface/interface'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'

// import { PublisherService } from '../utils/service/publisher.service'

export const privateRoute = express.Router()

const webResolver = web.getResolver()
const resolver = new Resolver(webResolver)
// const publisherService = new PublisherService()

privateRoute.post('/createWebDID', check('domain').not().isEmpty().trim(), async (req: Request, res: Response): Promise<void> => {
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
})

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
					selfDescription = Utils.generateLegalPerson(`${participantURL}#0`, didId, legalName, headquarterAddress, legalAddress, `${participantURL}#1`)
					const regVC = await Utils.generateRegistrationNumber(axios, didId, legalRegistrationType, legalRegistrationNumber, `${participantURL}%231`)
					const termsVC = await Utils.generateTermsAndConditions(axios, didId, `${participantURL}#2`)
					selfDescription['verifiableCredential'].push(regVC, termsVC)
				} else if (templateId === AppConst.SERVICE_OFFER) {
					const data = JSON.parse(he.decode(JSON.stringify(req.body.data)))
					const serviceComplianceUrl = tenant ? `https://${domain}/${tenant}/${data.fileName}` : `https://${domain}/.well-known/${data.fileName}`
					selfDescription = Utils.generateServiceOffer(participantURL, didId, serviceComplianceUrl, data)
					const { selfDescriptionCredential } = (await axios.get(participantURL)).data
					for (let index = 0; index < selfDescriptionCredential.verifiableCredential.length; index++) {
						const vc = selfDescriptionCredential.verifiableCredential[index]
						selfDescription.verifiableCredential.push(vc)
					}
				} else {
					res.status(422).json({
						error: `Type Not Supported`,
						message: AppMessages.DID_VALIDATION
					})
				}
				for (let index = 0; index < selfDescription['verifiableCredential'].length; index++) {
					const vc = selfDescription['verifiableCredential'][index]
					if (!selfDescription['verifiableCredential'][index].hasOwnProperty('proof')) {
						const proof = await Utils.generateProof(jsonld, he, axios, jose, crypto, vc, privateKeyUrl, didId, domain, tenant, AppConst.RSA_ALGO)
						selfDescription['verifiableCredential'][index].proof = proof
					}
				}
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
				console.log(JSON.stringify(error.response.data))
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
						credentialOffer?.headquarterAddress,
						credentialOffer?.legalAddress,
						''
					)
				}
				// normalize
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
						await verification(credentialContent, proof, res, true)
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

				// Check if the credential is of type VerifiableCredential or VerifiablePresentation, and separate credentialContent and proof accordingly
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
							responseObj.checkSignature = await verification(credentialContent, proof, res, true)
							if (typeof responseObj.checkSignature !== 'boolean') return
							break

						case AppConst.VERIFY_POLICIES[1]: //policy2
							console.log(`Executing ${policy} policy...`)
							const gxComplianceCheck = await verifyGxCompliance(credentialContent, res)
							responseObj.gxCompliance = gxComplianceCheck
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
							await verification(credentialContent, proof, res, true)
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
 * @returns boolean - true if the signature is verified
 */
async function verification(credentialContent: any, proof: any, res: Response, checkSSLwithRegistry: boolean) {
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
	const publicKeyJwk = ddo.didDocument.verificationMethod[0].publicKeyJwk
	const x5u = ddo.didDocument.verificationMethod[0].publicKeyJwk.x5u

	// get the SSL certificates from x5u url
	const certificates = (await axios.get(x5u)).data as string
	if (checkSSLwithRegistry) {
		// signature check against Gaia-x registry
		const registryRes = await Utils.validateSslFromRegistry(certificates, axios)
		if (!registryRes) {
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

	// verify Signature by retrieving the hash and then comparing it
	const verificationResult = await Utils.verify(jose, proof.jws.replace('..', `.${hash}.`), AppConst.RSA_ALGO, publicKeyJwk, hash)
	console.log(verificationResult ? `✅ ${AppMessages.SIG_VERIFY_SUCCESS}` : `❌ ${AppMessages.SIG_VERIFY_FAILED}`)
	return verificationResult
}

async function verifyGxCompliance(credentialContent: any, res: Response) {
	let url
	if (credentialContent.type.includes('VerifiablePresentation')) {
		url = credentialContent.verifiableCredential[0].credentialSubject.id
	} else {
		url = credentialContent.credentialSubject.id
	}

	const participantJson = await axios.get(url)
	const compCred = participantJson.data.complianceCredential
	const gxProof = compCred.proof
	delete compCred.proof
	const gxCred = compCred

	// verify signature
	const signVerify = await verification(gxCred, gxProof, res, false)

	// verify integrity hash
	const vcToHash = participantJson.data.selfDescriptionCredential.verifiableCredential[0]
	const integrityHash = `sha256-${createHash('sha256').update(JSON.stringify(vcToHash)).digest('hex')}`

	// compare hashes
	const credIntegrityHash = participantJson.data.complianceCredential.credentialSubject[0].integrity
	const integrityCheck = integrityHash === credIntegrityHash

	return signVerify && integrityCheck
}

privateRoute.post(
	'/get/trust-index',
	check('participantSD').not().isEmpty().trim(),
	check('serviceOfferingSD').not().isEmpty().trim(),
	async (req: Request, res: Response): Promise<void> => {
		try {
			const { participantSD, serviceOfferingSD } = req.body
			if (!Utils.IsValidURL(participantSD)) {
				console.error(`❌ Invalid participant self description url format`)
				throw new Error('Invalid participant self description url format')
			}
			if (!Utils.IsValidURL(serviceOfferingSD)) {
				console.error(`❌ Invalid service offering self description url format`)
				throw new Error('Invalid service offering self description url format')
			}

			const veracityResult = await calcVeracity(participantSD)
			const { veracity, certificateDetails } = veracityResult

			const transparency: number = await calcTransparency(serviceOfferingSD)
			console.log('transparency :-', transparency)

			const trustIndex: number = calcTrustIndex(veracity, transparency)
			console.log('trustIndex :-', trustIndex)

			res.status(200).json({
				message: 'Success',
				data: {
					veracity,
					transparency,
					trustIndex,
					certificateDetails
				}
			})
		} catch (error) {
			console.error(`❌ ${AppMessages.TRUST_INDEX_CALC_FAILED} : ${error}`)
			res.status(500).json({
				error: (error as Error).message,
				message: AppMessages.TRUST_INDEX_CALC_FAILED
			})
		}
	}
)

/**
 * @RefLinks
 * DID web with multiple keys https://www.w3.org/TR/did-core/#example-did-document-with-many-different-key-types
 * VC which has verification method pointing to a particular key https://www.w3.org/TR/vc-data-model/#example-a-simple-example-of-a-verifiable-credential
 * @dev Takes holder self description url as input and calculate veracity
 * @param participantUrl Holder self description url
 * @returns Object | undefined - undefined if bad data else return the veracity value and its certificate details
 */

const calcVeracity = async (
	participantUrl: any
): Promise<
	| {
			veracity: number
			certificateDetails: null
	  }
	| {
			veracity: number
			certificateDetails: X509CertificateDetail
	  }
> => {
	try {
		let veracity = 1
		let keypairDepth = 1
		let certificateDetails = null
		const participantJson = (await axios.get(participantUrl)).data
		if (participantJson && participantJson.verifiableCredential.length) {
			const participantSD = participantJson.verifiableCredential[0]
			const {
				id: holderDID,
				proof: { verificationMethod: participantVM }
			} = participantSD
			console.log(`holderDID :-${holderDID}  holderDID :- ${participantVM}`)

			const ddo = await Utils.getDDOfromDID(holderDID, resolver)
			if (!ddo) {
				// Bad Data
				console.error(`❌ DDO not found for given did: '${holderDID}' in proof`)
				throw new Error(`DDO not found for given did: '${holderDID}' in proof`)
			}
			const {
				didDocument: { verificationMethod: verificationMethodArray }
			} = ddo

			// There can be multiple verification methods in the did document but we have to find the one which has signed the holder vc
			// So verificationMethod mentioned in the proof of holder SD should have to be equal to the id filed in the verification method
			// participantSD.json >> proof >> verificationMethod === did.json >> verificationMethodArray >> verificationMethodObject >> id

			for (const verificationMethod of verificationMethodArray) {
				if (verificationMethod.id === participantVM && verificationMethod.publicKeyJwk) {
					const { x5u } = verificationMethod.publicKeyJwk

					// get the SSL certificates from x5u url
					const certificates = (await axios.get(x5u)).data as string
					// console.log('certificates :- ', certificates)

					const certArray = certificates.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)
					if (certArray?.length) {
						keypairDepth += certArray?.length // sum(len(keychain)
					}

					// getting object of a PEM encoded X509 Certificate.
					const certificate = new X509Certificate(certificates)
					certificateDetails = parseCertificate(certificate)

					break
				}
			}
			if (certificateDetails) {
				// As per formula(1 / len(keychain)), veracity will be 1 divided by number of signing
				// keypairs found in the certificate
				veracity = +(1 / keypairDepth).toFixed(2) //1 / len(keychain)
				return { veracity, certificateDetails }
			}
			console.error(`❌ Participant proof verification method and did verification method id not matched`)
			throw new Error('Participant proof verification method and did verification method id not matched')
		}
		console.error(`❌ Verifiable credential array not found in participant self description`)
		throw new Error('Verifiable credential array not found in participant self description')
	} catch (error) {
		console.error(error)
		throw error
	}
}

/**
 *	@Formula count(properties) / count(mandatoryproperties)
 *	Provided By 			Mandatory	(gx-service-offering:providedBy)
 *	Aggregation Of	 		Mandatory	(gx-service-offering:aggregationOf)
 *	Terms and Conditions 	Mandatory	(gx-service-offering:termsAndConditions)
 *	Policy	 				Mandatory	(gx-service-offering:policy)
 *	Data Account Export 	Mandatory	(gx-service-offering:dataExport)
 *	Name 					Optional	(gx-service-offering:name)
 *	Depends On	 			Optional  	(gx-service-offering:dependsOn)
 *	Data Protection Regime	Optional	(gx-service-offering:dataProtectionRegime)
 * @dev Takes service offering self description as input and calculates transparency
 * @param soUrl service offering self description url
 * @returns Number | undefined - undefined if bad data else returns the transparency value
 */
const calcTransparency = async (soUrl: any): Promise<number> => {
	const optionalProps: string[] = ['gx-service-offering:name', 'gx-service-offering:dependsOn', 'gx-service-offering:dataProtectionRegime']
	const totalMandatoryProps = 5
	let availOptProps = 0
	try {
		// get the json document of service offering
		const {
			selfDescriptionCredential: { credentialSubject }
		} = (await axios.get(soUrl)).data

		for (let index = 0; index < optionalProps.length; index++) {
			if (credentialSubject[optionalProps[index]]) {
				availOptProps++
			}
		}
		const transparency: number = (totalMandatoryProps + availOptProps) / totalMandatoryProps
		return transparency
	} catch (error) {
		console.error(`❌ Invalid service offering self description url :- error \n`)
		throw error
	}
}

/**
 * @formula trust_index = mean(veracity, transparency)
 * @dev takes the veracity and transparency as input and calculates trust index
 * @param veracity Veracity value
 * @param transparency Transparency value
 * @returns number - Trust index value
 */
const calcTrustIndex = (veracity: number, transparency: number): number => {
	const trustIndex: number = (veracity + transparency) / 2
	return trustIndex
}

/**
 * @dev Helps to parse and format x509Certificate data to return in response
 * @param certificate X509Certificate object
 * @returns X509CertificateDetail - Formatted X509Certificate object
 */
const parseCertificate = (certificate: X509Certificate): X509CertificateDetail => {
	const issuerFieldsString: string = certificate.issuer
	const issuerFieldsArray: string[] = issuerFieldsString.split('\n')

	const extractFieldValue = (fieldArray: string[], fieldName: string) => {
		const field: string | undefined = fieldArray.find((line: any) => line.startsWith(`${fieldName}=`))
		if (field) {
			return field.slice(fieldName.length + 1)
		}
		return null
	}
	// Extract individual fields from the subject string
	const subjectFieldsString: string = certificate.subject
	const subjectFieldsArray: string[] = subjectFieldsString.split('\n')

	const certificateDetails: X509CertificateDetail = {
		validFrom: certificate.validFrom,
		validTo: certificate.validTo,
		subject: {
			jurisdictionCountry: extractFieldValue(subjectFieldsArray, 'jurisdictionC'),
			jurisdictionSate: extractFieldValue(subjectFieldsArray, 'jurisdictionST'),
			jurisdictionLocality: extractFieldValue(subjectFieldsArray, 'jurisdictionL'),
			businessCategory: extractFieldValue(subjectFieldsArray, 'businessCategory'),
			serialNumber: extractFieldValue(subjectFieldsArray, 'serialNumber'),
			country: extractFieldValue(subjectFieldsArray, 'C'),
			state: extractFieldValue(subjectFieldsArray, 'ST'),
			locality: extractFieldValue(subjectFieldsArray, 'L'),
			organization: extractFieldValue(subjectFieldsArray, 'O'),
			commonName: extractFieldValue(subjectFieldsArray, 'CN')
		},
		issuer: {
			commonName: extractFieldValue(issuerFieldsArray, 'CN'),
			organization: extractFieldValue(issuerFieldsArray, 'O'),
			country: extractFieldValue(issuerFieldsArray, 'C')
		}
	}

	return certificateDetails
}
