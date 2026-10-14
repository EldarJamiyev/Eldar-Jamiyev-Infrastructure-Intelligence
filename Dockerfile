FROM node:22-bookworm-slim

WORKDIR /app

# Install system diagnostic tools for real I/O
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    iproute2 \
    traceroute \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --production --no-audit --no-fund

COPY . .

EXPOSE 8443

VOLUME ["/app/data"]

ENV EJII_PORT=8443
ENV EJII_HOST=0.0.0.0
ENV EJII_DATA_DIR=/app/data

CMD ["node", "src/server.js"]
