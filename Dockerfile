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

# Install runtime dependencies (nmap, curl, unzip, git for sync workers)
# Also install libraries needed for Metasploit native gems (nokogiri, pcaprub, pg, sqlite3, etc.)
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    unzip \
    git \
    python3 \
    python3-pip \
    ruby \
    ruby-dev \
    perl \
    default-jdk \
    netcat-openbsd \
    socat \
    gcc \
    g++ \
    make \
    # Libraries for Metasploit native gems
    libpcap-dev \
    libsqlite3-dev \
    libpq-dev \
    libxml2-dev \
    libxslt1-dev \
    libssl-dev \
    zlib1g-dev \
    libyaml-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install requests paramiko --break-system-packages || pip3 install requests paramiko \
    && gem install bundler -v 2.5.22 --no-document \
    && gem cleanup stringio 2>/dev/null || true

# Copy production dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p database logs

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
