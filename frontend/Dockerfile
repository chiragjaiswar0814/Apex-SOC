# syntax: docker/dockerfile:1

# ============================================================
# Stage 1: Node builder — installs deps & builds Vite bundle
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy manifests first for layer caching
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --frozen-lockfile

# Copy source and build
COPY . .
RUN npm run build


# ============================================================
# Stage 2: Nginx runtime
# ============================================================
FROM nginx:1.27-alpine AS runtime

LABEL maintainer="Apex-SOC Team"
LABEL description="Apex-SOC Frontend (React + Nginx)"

# Remove default nginx site
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Custom nginx config (handles SPA routing + API proxy)
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
