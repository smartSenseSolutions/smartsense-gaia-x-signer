import express from 'express'
import { privateRoute } from './private'

export const routesV1 = express.Router()
routesV1.use(privateRoute)
