import express, { Express } from 'express'
import bodyParser from 'body-parser'
import dotenv from 'dotenv'
import swaggerUi from 'swagger-ui-express'
import swaggerJSDoc from 'swagger-jsdoc'
import { routes } from './routes'
dotenv.config()

const app: Express = express()
const port = process.env.PORT

const options = {
	definition: {
		openapi: '3.0.1',
		info: {
			title: 'REST API for Gaia-X Singer Tool',
			version: '1.0.0'
		},
		schemes: ['http', 'https'],
		servers: [{ url: 'http://localhost:8000/' }]
	},
	apis: [`${__dirname}/routes/private.js`,`${__dirname}/routes/public.js`]
}
const swaggerSpec = swaggerJSDoc(options)
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))
// body-parser
app.use(bodyParser.json({ limit: '50mb', type: 'application/json' }))
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }))

// routes
app.use('/', routes)

app.listen(port, () => {
	console.log(`⚡️[server]: Server is running at http://localhost:${port}`)
})
