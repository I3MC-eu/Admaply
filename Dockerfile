FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_FILE=/usr/src/app/data/admaply.db

VOLUME ["/usr/src/app/data"]

EXPOSE 3000

CMD ["npm", "start"]
