export interface DidDocument {
	'@context': string[]
	id: string
	verificationMethod: any
	assertionMethod: string[]
	service?: Service[]
}

export interface Service {
    id:string
	type: string
	serviceEndpoint: string
}
