import axios from 'axios'
import { Resolver, VerificationMethod } from 'did-resolver'
import * as jose from 'jose'
import { VerifiableCredentialDto, SignatureDto } from '../interface/interface'
import jsonld from 'jsonld'
import { Utils } from '../utils/common-functions'
import { AppConst, AppMessages } from '../utils/constants'
import web from 'web-did-resolver'
export class Helper {
	webResolver = web.getResolver()
	resolver = new Resolver(this.webResolver)

	/**
	 * @dev takes the credential and proof, and verifies the signature is valid or not
	 * @param credentialContent the credential part which will be hashed for proof
	 * @param proof the proof obj
	 * @returns boolean - true if the signature is verified
	 */

	verification = async (credentialContent: VerifiableCredentialDto, proof: SignatureDto, checkSSLwithRegistry: boolean) => {
		// eslint-disable-next-line no-useless-catch
		try {
			// check if proof is of type JsonWebSignature2020
			if (proof.type !== 'JsonWebSignature2020') {
				console.log(`❌ signature type: '${proof.type}' not supported`)
				throw new Error(`signature type: '${proof.type}' not supported`)
			}

			// get the DID Document
			const ddo = await Utils.getDDOfromDID(proof.verificationMethod, this.resolver)
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
}
export default new Helper()
