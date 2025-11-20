# Multi-stage Dockerfile for Enterprise API Service
# This file builds both the API backend and web frontend in a single optimized image

FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json pnpm-lock.yaml* ./
RUN corepack enable pnpm && pnpm install --frozen-lockfile

# Build API Backend
FROM base AS api-builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma client for API
RUN npx prisma generate

# Build the API backend
RUN npm run build:backend

# Database setup and seeding stage
FROM base AS db-setup
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=api-builder /app/prisma ./prisma
COPY --from=api-builder /app/api/prisma ./api/prisma
COPY prisma/seed-test-user.ts ./

# Generate Prisma client
RUN npx prisma generate

# Create database and run migrations
RUN npx prisma db push --accept-data-loss

# Seed the database with test user
RUN npx tsx prisma/seed-test-user.ts

# Build Web Frontend
FROM base AS web-builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the web frontend
RUN npm run build

# Production image
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

# Install runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create a non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nodejs

# Copy built applications
COPY --from=api-builder /app/api/dist ./api/dist
COPY --from=api-builder /app/api/prisma ./api/prisma
COPY --from=db-setup /app/prisma ./prisma
COPY --from=web-builder --chown=nodejs:nodejs /app/.next/standalone ./
COPY --from=web-builder --chown=nodejs:nodejs /app/.next/static ./.next/static
COPY --from=web-builder /app/public ./public
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./package.json
COPY --from=deps /app/pnpm-lock.yaml ./pnpm-lock.yaml
COPY docker-entrypoint.sh ./docker-entrypoint.sh

# Create necessary directories
RUN mkdir -p /app/logs && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose ports
EXPOSE 3000 8080

# Health checks
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health && curl -f http://localhost:3000/api/health || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Use custom entrypoint script
ENTRYPOINT ["./docker-entrypoint.sh"]