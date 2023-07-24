export interface DidDocument {
	'@context': string[]
	id: string
	verificationMethod: any
	assertionMethod: string[]
	service?: Service[]
}

export interface Service {
	id: string
	type: string
	serviceEndpoint: string
}

export interface X509CertificateDetail {
	validFrom: string
	validTo: string
	subject: {
		jurisdictionCountry: string | null
		jurisdictionSate: string | null
		jurisdictionLocality: string | null
		businessCategory: string | null
		serialNumber: string | null
		country: string | null
		state: string | null
		locality: string | null
		organization: string | null
		commonName: string | null
	}
	issuer: {
		commonName: string | null
		organization: string | null
		country: string | null
	}
}
