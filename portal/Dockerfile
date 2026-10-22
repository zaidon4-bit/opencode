FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/var/data \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

RUN npm install --global opencode-ai@1.19.3

COPY package.json ./package.json
RUN npm install --omit=dev

COPY server.js ./server.js
COPY public ./public

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /var/data \
    && chown -R appuser:appuser /app /var/data

USER appuser
EXPOSE 3000
CMD ["node", "server.js"]
