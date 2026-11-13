---
name: docker-patterns
description: Dockerfile best-practices, multi-stage builds, docker-compose, production hardening
metadata:
  type: skill
  triggers: ["docker", "dockerfile", "container", "docker-compose", "containerize"]
---

# Docker Patterns

## Multi-stage Dockerfile (Node.js)
```dockerfile
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder /app/dist ./dist
COPY --from=deps /app/node_modules ./node_modules
USER appuser
EXPOSE 3000
CMD ["node", "dist/main.js"]
```

## docker-compose.yml
```yaml
services:
  app:
    build: .
    ports: ["3000:3000"]
    depends_on:
      db:
        condition: service_healthy
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: mydb
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d mydb"]
      interval: 5s
      retries: 5
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

## Rules
- Never run as root in production
- `.dockerignore`: exclude `node_modules`, `.git`, `.env`
- Pin base image versions (not `latest`)
- Healthchecks on all stateful services
