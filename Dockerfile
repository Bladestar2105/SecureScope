# SecureScope - Network Security Audit Tool
# Multi-stage Docker build

# ==========================================
# Stage 1: Builder
# ==========================================
FROM node:20-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install production dependencies (and build native modules)
RUN npm ci --only=production && npm cache clean --force

# ==========================================
# Stage 2: Runner
# ==========================================
FROM node:20-slim

WORKDIR /app

# Install runtime dependencies (nmap)
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r securescope && useradd -r -g securescope securescope

# Copy production dependencies from builder
COPY --from=builder --chown=securescope:securescope /app/node_modules ./node_modules

# Copy application code
COPY --chown=securescope:securescope . .

# Create necessary directories with correct permissions
RUN mkdir -p database logs && \
    chown -R securescope:securescope database logs

# Switch to non-root user
USER securescope

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD node -e "const http = require('http'); http.get('http://localhost:3000/api/auth/status', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start the application
CMD ["node", "server.js"]
