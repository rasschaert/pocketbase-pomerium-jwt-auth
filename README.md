# PocketBase + Pomerium Zero JWT Integration

**Trust-Based Architecture for Pomerium Zero** 🎯

Auto-provisions PocketBase users from Pomerium Zero JWT claims. Built for network-secured environments where Pomerium handles all authentication.

## ⚠️ **SECURITY WARNING**

**🚨 THIS CODE DOES NOT VERIFY JWT SIGNATURES! 🚨**

This implementation assumes:

- **Pomerium Zero is the ONLY path to reach PocketBase**
- **Network-level security prevents direct access**
- **JWT signature validation happens at Pomerium**
- **PocketBase trusts all incoming JWTs**

**Only use this if PocketBase is completely isolated behind Pomerium!**

## 🏗️ Architecture

```
Internet → Pomerium Zero (validates JWTs) → Network Barrier → PocketBase (trusts claims)
```

## � Building the Container

```bash
# Build the image
docker build -t pocketbase-pomerium .

# Or use docker-compose
docker-compose build
```

## 🚀 Running the Container

### Basic Docker Run

```bash
docker run -d \
  --name pocketbase \
  -p 8090:8090 \
  -v ./data:/pb_data \
  pocketbase-pomerium
```

### With Docker Compose

```yaml
services:
  pocketbase:
    build: .
    ports:
      - "8090:8090"
    volumes:
      - ./data:/pb_data
    environment:
      - DEBUG=false
      - JWT_HEADER=X-Pomerium-Jwt-Assertion
```

## ⚙️ Configuration

Only 2 optional environment variables:

- `DEBUG=true/false` - Enable debug logging
- `JWT_HEADER=X-Custom-Header` - Change JWT header name

## 🔧 Pomerium Zero Setup

Configure Pomerium to forward JWTs:

```yaml
routes:
  - from: https://your-app.pomerium.app
    to: http://your-server:8090
    pass_identity_headers: true
    set_request_headers:
      X-Pomerium-Jwt-Assertion: "{{ .pomerium.jwt }}"
```

## How It Works

**Trust-Based Authentication Flow:**

1. User hits Pomerium Zero URL → Pomerium validates JWT signatures
2. Pomerium forwards request → Includes JWT in `X-Pomerium-Jwt-Assertion` header
3. PocketBase extracts claims → **NO signature validation** (trusts Pomerium)
4. User auto-created → From JWT email, name, sub, etc.

**Zero-Crypto JWT Processing:**

```go
// Just parse the JSON payload - no validation!
func extractJWTClaims(token string) (*PomeriumClaims, error) {
    parts := strings.Split(token, ".")
    payload, _ := base64.URLEncoding.DecodeString(parts[1])

    var claims PomeriumClaims
    json.Unmarshal(payload, &claims)
    return &claims, nil  // Trust Pomerium's validation
}
```

## ⚠️ **IMPORTANT REMINDERS**

- **This code does NOT verify JWT signatures**
- **Only use behind Pomerium Zero in isolated networks**
- **Pomerium must be the ONLY way to reach PocketBase**
- **Network security is your authentication boundary**

## 📄 License

MIT - Use freely (but securely)!
