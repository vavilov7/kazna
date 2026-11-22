FROM node:26.13.1-slim

WORKDIR /client
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY login.mjs ./

ENTRYPOINT ["node", "login.mjs"]
