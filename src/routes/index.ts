import express from 'express'
import { privateRoute } from './private'
import { publicRoute } from './public'

export const routes = express.Router()
routes.use(privateRoute)
routes.use(publicRoute)
