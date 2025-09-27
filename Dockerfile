# Ultra-Simple Trust-Based PocketBase
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o pocketbase-auth .

# Minimal runtime
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata wget
COPY --from=builder /app/pocketbase-auth /pocketbase-auth

EXPOSE 8090
VOLUME ["/pb_data"]

ENTRYPOINT ["/pocketbase-auth"]
CMD ["serve", "--http=0.0.0.0:8090"]
