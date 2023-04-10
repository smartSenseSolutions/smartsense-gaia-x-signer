import express, { Express } from 'express'
import bodyParser from 'body-parser'
import dotenv from 'dotenv'
import swaggerUi from 'swagger-ui-express'
import { routes } from './routes'
dotenv.config()

const app: Express = express()
const port = process.env.PORT

import * as swaggerDocument from './swagger.json'
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))
// body-parser
app.use(bodyParser.json({ limit: '50mb', type: 'application/json' }))
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }))

// routes
app.use('/', routes)

app.listen(port, () => {
	console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})
