# Multi-stage Dockerfile - frontend + backend
FROM node:20-alpine AS base

# Base dependencies
RUN apk add --no-cache libc6-compat curl bash
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@latest --activate

# Install dependencies
FROM base AS deps
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# Build backend
FROM base AS api-builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx prisma generate
RUN pnpm run build:backend

# Build frontend
FROM base AS web-builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx prisma generate
RUN pnpm run build

# Production image
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV DATABASE_URL="file:./dev.db"
ENV API_PORT=8080
ENV PORT=3000

RUN apk add --no-cache dumb-init curl bash && rm -rf /var/cache/apk/*

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nodejs

# Copy built apps
COPY --from=api-builder /app/api/dist ./api/dist
COPY --from=api-builder /app/api/prisma ./api/prisma
COPY --from=api-builder /app/prisma ./prisma
COPY --from=web-builder --chown=nodejs:nodejs /app/.next/standalone ./
COPY --from=web-builder --chown=nodejs:nodejs /app/.next/static ./.next/static
COPY --from=web-builder /app/public ./public
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY --from=deps /app/pnpm-lock.yaml ./pnpm-lock.yaml

RUN mkdir -p /app/logs && chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000 8080

# CMD final pour container stable
CMD ["dumb-init", "--", "sh", "-c", "\
  echo 'Starting Sky Genesis Enterprise API Service...'; \
  echo 'Frontend will start on port $PORT'; \
  echo 'Backend will start on port $API_PORT'; \
  \
  # Démarrer le backend en arrière-plan \
  echo 'Starting backend on port $API_PORT...' && \
  API_PORT=$API_PORT pnpm run start:backend & \
  \
  # Attendre un peu que le backend démarre \
  sleep 5; \
  \
  # Démarrer le frontend \
  echo 'Starting frontend on port $PORT...' && \
  PORT=$PORT pnpm run start; \
  \
  # Le script attendra que le frontend se termine (jamais) \
  wait"]