export class AppConst {
	static readonly RSA_ALGO = 'PS256'
	static readonly LEGAL_PARTICIPANT = 'LegalParticipant'
	static readonly SERVICE_OFFER = 'ServiceOffering'
	static readonly FLATTEN_ENCRYPT_ALGORITHM = 'RSA-OAEP-256'
	static readonly FLATTEN_ENCRYPT_ENCODING = 'A256GCM'
	static readonly VERIFY_POLICIES = ['checkSignature', 'gxCompliance']
	static readonly REQUEST_TYPES = ['API', 'email', 'webform', 'unregisteredLetter', 'registeredLetter', 'supportCenter']
	static readonly ACCESS_TYPES = ['digital', 'physical']
}

export class AppMessages {
	static readonly CLAIM_SIG_VERIFY_FAILED = 'Claim signature verification failed'
	static readonly DID_SUCCESS = 'DID created successfully.'
	static readonly DID_FAILED = 'DID creation failed.'
	static readonly DID_VALIDATION = 'DID validation failed.'
	static readonly KEYPAIR_VALIDATION = 'Key pair validation failed'
	static readonly VC_SUCCESS = 'VC created successfully.'
	static readonly VC_VALIDATION = 'VC validation failed.'
	static readonly VC_FAILED = 'VC creation failed.'
	static readonly VP_SUCCESS = 'VP created successfully.'
	static readonly VP_FAILED = 'VP creation failed.'
	static readonly VP_VALIDATION = 'VP validation failed.'
	static readonly SIG_VERIFY_VALIDATION = 'Signature verification api validation failed.'
	static readonly SIG_VERIFY_SUCCESS = 'Signature verification successful'
	static readonly SIG_VERIFY_FAILED = 'Signature verification failed'
	static readonly CERT_VALIDATION_FAILED = 'Certificates verification failed against the Gaia-x Registry'
	static readonly PUB_KEY_MISMATCH = 'Public Key from did and SSL certificates do not match'
	static readonly ONLY_JWS2020 = 'Only JsonWebSignature2020 is supported'
	static readonly PARTICIPANT_DID_FETCH_FAILED = 'Participant DID fetching failed'
	static readonly PARTICIPANT_VC_FOUND_FAILED = 'Participant VC not found'
	static readonly SO_SD_FETCH_FAILED = 'Service offering self description fetching failed'
	static readonly LABEL_LEVEL_CALC_FAILED_INVALID_KEY = 'Rule point key not found in criteria json - '
}

export const LABEL_LEVEL_RULE: any = {
	BC: [
		'P1.1.1',
		'P1.1.3',
		'P1.1.4',
		'P1.2.1',
		'P1.2.2',
		'P1.2.3',
		'P1.2.4',
		'P1.2.5',
		'P1.2.6',
		'P1.2.7',
		'P1.2.8',
		'P1.2.9',
		'P1.2.10',
		'P1.3.1',
		'P1.3.2',
		'P1.3.3',
		'P1.3.4',
		'P1.3.5',
		'P2.1.2',
		'P2.1.3',
		'P2.2.1',
		'P2.2.2',
		'P2.2.3',
		'P2.2.5',
		'P2.2.6',
		'P2.2.7',
		'P2.3.2',
		'P2.3.3',
		'P3.1.1',
		'P3.1.2',
		'P3.1.3',
		'P3.1.4',
		'P3.1.5',
		'P3.1.6',
		'P3.1.7',
		'P3.1.8',
		'P3.1.9',
		'P3.1.10',
		'P3.1.11',
		'P3.1.12',
		'P3.1.13',
		'P3.1.14',
		'P3.1.15',
		'P3.1.16',
		'P3.1.17',
		'P3.1.18',
		'P3.1.19',
		'P3.1.20',
		'P4.1.1',
		'P4.1.2',
		'P5.2.1'
	],
	L1: ['P1.1.2', 'P2.1.1', 'P2.2.4', 'P2.3.1']
	// L2: ['P5.1.1'],
	// L3: ['P5.1.2', 'P5.1.3', 'P5.1.4', 'P5.1.5', 'P5.1.6', 'P5.1.7']
}
