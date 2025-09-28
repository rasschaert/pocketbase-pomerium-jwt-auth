# PocketBase + Pomerium Zero JWT Integration

PocketBase offers a lot of functionality out of the box, but it allows you to [add your own logic on top in Go or Javascript](https://pocketbase.io/docs/use-as-framework/).

By default, PocketBase allows unauthenticated requests to it's "collections". This projects adds a simple middleware to:

- Require either a valid Authorization header (Bearer token) or a Pomerium JWT header for collection requests
- If the Pomerium JWT header is present, auto-provision a PocketBase user from the JWT claims (email, name, sub, etc)

Endpoints that are not for collection requests are not impacted by this middlware. This way Admin users can log in with username/password via the standard PocketBase admin UI, while regular users accessing collections are auto-provisioned via Pomerium Zero.

## ⚠️ **SECURITY WARNING**

**🚨 THIS CODE DOES NOT (YET) VERIFY JWT SIGNATURES! 🚨**

## Building the Container

```bash
# Build the image
docker build -t pocketbase-pomerium-jwt-auth .

# Or use docker-compose
docker-compose build
```

## Running the Container

### Basic Docker Run

```bash
docker run -d \
  --name pocketbase-pomerium-jwt-auth \
  -p 8090:8090 \
  -v ./data:/pb_data \
  pocketbase-pomerium-jwt-auth
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

## Configuration

Only 2 optional environment variables:

- `DEBUG=true/false` - Enable debug logging
- `JWT_HEADER=X-Custom-Header` - Change JWT header name

## Pomerium Zero Setup

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

### For Collection Requests (`/api/collections/*`)

1. User hits Pomerium Zero URL → Pomerium validates JWT signatures
2. Pomerium forwards request → Includes JWT in `X-Pomerium-Jwt-Assertion` header
3. PocketBase middleware checks for JWT or valid Authorization Bearer token
4. If JWT present: User auto-created/updated from JWT claims (email, name, sub, etc.)
5. If Bearer token: Validates against existing PocketBase user/admin authentication

### For Admin Endpoints (`/api/_*` and `/api/admins/*`)

- **No additional authentication required** - uses standard PocketBase admin authentication
- Admin users can access the PocketBase admin UI normally at `/api/_/`
- API endpoints for admin operations work with standard PocketBase admin tokens

## License

MIT
