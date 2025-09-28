# PocketBase with Pomerium JWT Authentication
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go .

# Build the application natively
RUN CGO_ENABLED=0 go build \
    -ldflags="-w -s" \
    -o pocketbase-pomerium-jwt-auth .

# Minimal runtime image
FROM alpine:3.22

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1000 pocketbase && \
    adduser -D -s /bin/sh -u 1000 -G pocketbase pocketbase

# Copy binary from builder
COPY --from=builder /app/pocketbase-pomerium-jwt-auth /usr/local/bin/pocketbase-pomerium-jwt-auth

# Make binary executable
RUN chmod +x /usr/local/bin/pocketbase-pomerium-jwt-auth

# Create data directory and set permissions
RUN mkdir -p /pb_data && \
    chown -R pocketbase:pocketbase /pb_data

# Switch to non-root user
USER pocketbase

# Expose port
EXPOSE 8090

# Set up volume
VOLUME ["/pb_data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/api/health || exit 1

# Set entrypoint and default command
ENTRYPOINT ["/usr/local/bin/pocketbase-pomerium-jwt-auth"]
CMD ["serve", "--http=0.0.0.0:8090"]
