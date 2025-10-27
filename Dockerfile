# ----------------------------
# Étape 1 : Build Backend Rust
# ----------------------------
FROM debian:13-slim AS rust-builder

RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /api
COPY api/Cargo.toml ./
COPY api/src ./src
RUN cargo build --release

# ----------------------------
# Étape 2 : Build Frontend Next.js
# ----------------------------
FROM node:20-bullseye-slim AS nextjs-builder

WORKDIR /app
COPY package*.json ./
RUN pnpm install
COPY app/ ./   
RUN pnpm run build

# ----------------------------
# Étape 3 : Image finale avec Nginx
# ----------------------------
FROM debian:13-slim

# Installer runtime + Nginx
RUN apt-get update && apt-get install -y \
    libssl-dev ca-certificates curl nodejs npm nginx && \
    rm -rf /var/lib/apt/lists/*

# Backend Rust
COPY --from=rust-builder /api/target/release/backend /usr/local/bin/backend

# Frontend Next.js
COPY --from=nextjs-builder /app/.next /app/.next
COPY --from=nextjs-builder /app/package*.json /app/
WORKDIR /app
RUN pnpm install --omit=dev

# Copier la configuration Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Exposer ports
EXPOSE 80 443

# Commande pour lancer backend + Nginx
CMD ["sh", "-c", "backend & nginx -g 'daemon off;'"]