# Multi-stage Dockerfile for Enterprise API Service (pnpm version)
# Builds backend and frontend in a single image

FROM node:20-alpine AS base

# Base dependencies
RUN apk add --no-cache libc6-compat curl bash
WORKDIR /app

# Install pnpm
RUN corepack enable pnpm

# Install dependencies
FROM base AS deps
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# Build API Backend
FROM base AS api-builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx prisma generate
RUN pnpm run build:backend

# Build Web Frontend
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
ENV API_PORT=8085       
ENV PORT=4000           

# Runtime dependencies
RUN apk add --no-cache dumb-init curl bash && rm -rf /var/cache/apk/*

# Create non-root user
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
COPY docker-entrypoint.sh ./docker-entrypoint.sh
COPY prisma/seed-test-user.ts ./prisma/seed-test-user.ts
COPY .env.example .env

# Permissions & logs
RUN mkdir -p /app/logs && chown -R nodejs:nodejs /app
USER nodejs

# Expose ports
EXPOSE 4000 8085

# Health checks
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:4000/ || exit 1; curl -f http://localhost:8085/api/v1/health || exit 1

# Entrypoint using dumb-init
ENTRYPOINT ["dumb-init", "--", "./docker-entrypoint.sh"]