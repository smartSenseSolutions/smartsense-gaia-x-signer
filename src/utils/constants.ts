export class AppConst {
	static readonly RSA_ALGO = 'PS256'
	static readonly LEGAL_PARTICIPANT = 'LegalParticipant'
	static readonly SERVICE_OFFER = 'ServiceOfferingExperimental'
}

export class AppMessages {
	static readonly DID_SUCCESS = 'DID created successfully.'
	static readonly DID_FAILED = 'DID creation failed.'
	static readonly DID_VALIDATION = 'DID validation failed.'
	static readonly VP_SUCCESS = 'VP created successfully.'
	static readonly VP_FAILED = 'VP creation failed.'
	static readonly VP_VALIDATION = 'VP validation failed.'
	static readonly SIG_VERIFY_SUCCESS = 'Signature verification successful'
	static readonly SIG_VERIFY_FAILED = 'Signature verification failed'
}
