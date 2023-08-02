import supertest from 'supertest'
import app from '..'
import STATUS_CODES from 'http-status-codes'
import { Utils } from '../utils/common-functions'
import { AppMessages } from '../utils/constants'

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
//mocking - Utils
jest.mock('../utils/common-functions', () => {
	return {
		...jest.requireActual('../utils/common-functions'),

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		fetchParticipantJson: async (participantUrl: string) => {
			return participantJson
		}
	}
})
describe('/verifyLegalParticipant', () => {
	describe('Failing Cases', () => {
		describe('validation error', () => {
			it('empty body', async () => {
				const error = {
					error: "Invalid value of param 'policies'",
					message: 'Signature verification api validation failed.'
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.UNPROCESSABLE_ENTITY)
						expect(response.body).toEqual(error)
					})
			})
			it('participantUrl is invalid', async () => {
				const body = {
					policies: ['integrityCheck', 'holderSignature', 'complianceSignature', 'complianceCheck'],
					participantUrl: ''
				}
				const error = {
					error: "Invalid value of param 'participantUrl'",
					message: 'Signature verification api validation failed.'
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.UNPROCESSABLE_ENTITY)
						expect(response.body).toEqual(error)
					})
				body.participantUrl = 'abc'

				await supertest(app)
					.post(`/v1//verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.UNPROCESSABLE_ENTITY)
						expect(response.body).toEqual(error)
					})
			})
			it('policies is invalid', async () => {
				const body: {
					policies: string[]
					participantUrl: string
				} = {
					policies: [],
					participantUrl: 'https://greenworld.proofsense.in/.well-known/participant.json'
				}
				const error = {
					error: "Invalid value of param 'policies'",
					message: 'Signature verification api validation failed.'
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.UNPROCESSABLE_ENTITY)
						expect(response.body).toEqual(error)
					})
				body.policies = ['invalid policies']
				await supertest(app)
					.post(`/v1//verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.UNPROCESSABLE_ENTITY)
						expect(response.body).toEqual(error)
					})
			})
		})
		describe('general failing case', () => {
			it('fail to fetch participant json from url', async () => {
				jest.spyOn(Utils, 'fetchParticipantJson').mockImplementation(async () => {
					throw new Error('Fail to fetch')
				})
				const body = {
					policies: ['integrityCheck', 'holderSignature', 'complianceSignature', 'complianceCheck'],
					participantUrl: 'https://greenyyyworld.proofsense.in/.well-known/participant.json'
				}
				const error = {
					error: 'Fail to fetch',
					message: 'Signature verification failed'
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.INTERNAL_SERVER_ERROR)
						expect(response.body).toEqual(error)
					})
				jest.resetAllMocks()
			})
			it('fetched participantJson in invalid form', async () => {
				jest.spyOn(Utils, 'fetchParticipantJson').mockImplementation(async () => {
					return {}
				})
				const body = {
					policies: ['integrityCheck', 'holderSignature', 'complianceSignature', 'complianceCheck'],
					participantUrl: 'https://greenworld.proofsense.in/.well-known/participant.json'
				}
				const error = {
					error: `VC not found`,
					message: AppMessages.PARTICIPANT_VC_FOUND_FAILED
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.BAD_REQUEST)
						expect(response.body).toEqual(error)
					})
				jest.resetAllMocks()
			})
			it('vc not in form of array', async () => {
				jest.spyOn(Utils, 'fetchParticipantJson').mockImplementation(async () => {
					return { ...participantJson, selfDescriptionCredential: { ...participantJson.selfDescriptionCredential, verifiableCredential: 'verifiable credential' } }
				})
				const body = {
					policies: ['integrityCheck', 'holderSignature', 'complianceSignature', 'complianceCheck'],
					participantUrl: 'https://greenworld.proofsense.in/.well-known/participant.json'
				}
				const error = {
					error: `VC not valid`,
					message: AppMessages.PARTICIPANT_VC_INVALID
				}
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.BAD_REQUEST)
						expect(response.body).toEqual(error)
					})

				jest.resetAllMocks()

				jest.spyOn(Utils, 'fetchParticipantJson').mockImplementation(async () => {
					const mockParticipantJson = participantJson
					delete mockParticipantJson.selfDescriptionCredential.verifiableCredential
					console.log({ ...mockParticipantJson.selfDescriptionCredential.verifiableCredential })
					return { ...mockParticipantJson }
				})
				error.error = 'VC not found'
				error.message = AppMessages.PARTICIPANT_VC_FOUND_FAILED
				await supertest(app)
					.post(`/v1/verifyLegalParticipant`)
					.send(body)
					.expect((response) => {
						expect(response.status).toBe(STATUS_CODES.BAD_REQUEST)
						expect(response.body).toEqual(error)
					})

				jest.resetAllMocks()
			})
		})
	})
})