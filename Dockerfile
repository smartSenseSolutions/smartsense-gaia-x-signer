FROM node:16.13.1

WORKDIR /usr/src/app

COPY ./package*.json ./

RUN npm ci

COPY . .

RUN npm run build

RUN npm install pm2@5.2.0 -g

CMD ["pm2-runtime","--raw","dist/index.js","--name=smartsense-gaia-x-signer","--no-daemon"]
