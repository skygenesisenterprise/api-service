# Use Node.js 20 LTS as base image
FROM node:20-alpine AS base

# Install pnpm
RUN npm install -g pnpm

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Copy Prisma schema for client generation
COPY prisma ./prisma

# Generate Prisma client
RUN pnpm run db:generate

# Build the frontend application with optimizations
RUN pnpm run build

# Build the backend application
RUN pnpm run build:backend

# Production stage
FROM node:20-alpine AS production

# Install pnpm
RUN npm install -g pnpm

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Install only production dependencies
RUN pnpm install --frozen-lockfile --prod

# Install tsx for backend runtime
RUN npm install -g tsx

# Copy Prisma schema
COPY --from=base /app/prisma ./prisma

# Generate Prisma client in production
RUN pnpm run db:generate

# Copy built application from base stage
COPY --from=base /app/.next/standalone ./
COPY --from=base /app/.next/static ./.next/static
COPY --from=base /app/public ./public
COPY --from=base /app/api ./api
COPY --from=base /app/api/dist ./api/dist

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose ports
EXPOSE 3000 8080

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV BACKEND_PORT=8080
ENV NEXT_TELEMETRY_DISABLED=1
ENV ENVIRONMENT=production
ENV HEALTH_PATH=/home
ENV DATABASE_URL="file:./dev.db"
ENV PRISMA_GENERATE_DATAPROXY=false

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const http = require('http'); const checkPath = process.env.HEALTH_PATH || '/home'; http.get('http://localhost:3000' + checkPath, (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start the application
CMD ["sh", "-c", "HOSTNAME=0.0.0.0 node server.js"]