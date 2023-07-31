import express, { Request, Response } from 'express'

import { AppMessages } from '../utils/constants'

export const privateRoute = express.Router()

privateRoute.post('/LegalParticipantOnGaiaX', async (req: Request, res: Response): Promise<void> => {
	try {
		const { privateKey, legalParticipant, legalRegistrationNumber, gaiaXTermsAndConditions } = req.body
		res.status(200).json({
			data: { legalRegistrationNumber },
			message: AppMessages.DID_SUCCESS
		})
	} catch (e) {
		res.status(500).json({
			error: (e as Error).message,
			message: AppMessages.DID_FAILED
		})
	}
})

privateRoute.post('/service-offering/gx', async (req: Request, res: Response): Promise<void> => {
	try {
		const { privateKey, legalParticipant, legalRegistrationNumber, gaiaXTermsAndConditions } = req.body
		res.status(200).json({
			data: { legalRegistrationNumber },
			message: AppMessages.SD_SIGN_SUCCESS
		})
	} catch (e) {
		res.status(500).json({
			error: (e as Error).message,
			message: AppMessages.SD_SIGN_FAILED
		})
	}
})
