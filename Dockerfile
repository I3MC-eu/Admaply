FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/captain/data
ENV DB_FILE=/captain/data/admaply.db
ENV DB_JSON_FILE=/captain/data/admaply.json

VOLUME ["/captain/data"]

EXPOSE 3000

CMD ["npm", "start"]
