# auth-service

Lightweight authentication service written in Go. Implements JWT (RS256) access tokens, secure refresh token rotation via HttpOnly cookies, PostgreSQL session storage, and a JWKS endpoint for public key distribution across microservices.

## Features

- JWT access tokens signed with RS256 (asymmetric keys)
- Refresh token rotation with PostgreSQL-backed session storage
- Tokens delivered as **HttpOnly cookies** (not exposed to JavaScript)
- JWKS endpoint (`/.well-known/jwks.json`) for token verification by other services
- Bcrypt password hashing
- IP-based rate limiting on auth endpoints
- Swagger UI — available only when `ENV=local`
- Database migrations via `golang-migrate`

## Tech Stack

| Layer | Library |
|---|---|
| HTTP router | [chi](https://github.com/go-chi/chi) |
| JWT | [golang-jwt/jwt v5](https://github.com/golang-jwt/jwt) |
| Database | PostgreSQL via [pgx v5](https://github.com/jackc/pgx) |
| Config | [cleanenv](https://github.com/ilyakaznacheev/cleanenv) + godotenv |
| Migrations | [golang-migrate](https://github.com/golang-migrate/migrate) |
| Docs | [swaggo/swag](https://github.com/swaggo/swag) |

## Quick Start

### 1. Generate RSA keys

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### 2. Configure environment

Copy the example and fill in your values:

```bash
cp .env.example .env
```

`.env` for local development:

```env
ENV=local

DATABASE_URL=postgres://postgres:postgres@postgres:5432/authdb?sslmode=disable

JWT_ISSUER=auth-mytierlist
JWT_KEY_ID=key-1
JWT_PRIVATE_KEY_PATH=/app/keys/private.pem
JWT_PUBLIC_KEY_PATH=/app/keys/public.pem

HTTP_ADDRESS=:8080
HTTP_TIMEOUT=5s
HTTP_IDLE_TIMEOUT=60s

ACCESS_TTL=15m
REFRESH_TTL=720h
BCRYPT_COST=10
```

### 3. Run with Docker Compose

```bash
docker compose up --build
```

Starts PostgreSQL, runs migrations, and launches the service on port `8080`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENV` | `local` | `local` enables Swagger UI; `prod` disables it |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `JWT_ISSUER` | `auth-mytierlist` | JWT `iss` claim |
| `JWT_KEY_ID` | `key-1` | Key ID used in JWKS |
| `JWT_PRIVATE_KEY_PATH` | — | Path to RSA private key (PEM) |
| `JWT_PUBLIC_KEY_PATH` | — | Path to RSA public key (PEM) |
| `HTTP_ADDRESS` | `:8080` | Listen address |
| `HTTP_TIMEOUT` | `5s` | Read/write timeout |
| `HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive timeout |
| `ACCESS_TTL` | `15m` | Access token lifetime |
| `REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `BCRYPT_COST` | `10` | Bcrypt cost factor (use 12+ in production) |

## API Endpoints

Base path: `/api/v1`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | — | Register a new user |
| `POST` | `/auth/login` | — | Authenticate; sets `access_token` + `refresh_token` cookies |
| `POST` | `/auth/refresh` | cookie | Rotate refresh token; sets new cookies |
| `POST` | `/auth/logout` | cookie | Revoke session; clears cookies |
| `GET` | `/auth/me` | cookie | Get current user info |
| `GET` | `/.well-known/jwks.json` | — | Public key set for RS256 verification |
| `GET` | `/swagger/*` | — | Swagger UI (local only) |
| `GET` | `/ready` | — | Readiness probe |

### Auth flow

Tokens are stored in HttpOnly cookies — the browser sends them automatically, no JavaScript access needed.

| Cookie | HttpOnly | SameSite | Lifetime |
|---|---|---|---|
| `access_token` | yes | Strict | 15 min |
| `refresh_token` | yes | Strict | 30 days |

### Example: Register

```bash
curl -c cookies.txt -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"login": "alice", "password": "secret"}'
```

Cookies are set automatically. Subsequent requests:

```bash
# Get current user (cookie sent automatically)
curl -b cookies.txt http://localhost:8080/api/v1/auth/me

# Refresh tokens
curl -b cookies.txt -c cookies.txt -X POST http://localhost:8080/api/v1/auth/refresh

# Logout
curl -b cookies.txt -X POST http://localhost:8080/api/v1/auth/logout
```

## Project Structure

```
.
├── cmd/api/          # Entry point
├── docs/             # Swagger generated docs
├── internal/
│   ├── app/          # Application wiring
│   ├── config/       # Config loading (cleanenv)
│   ├── logger/       # slog-based logger
│   ├── pkg/
│   │   ├── security/ # Bcrypt hasher
│   │   └── token/    # JWT manager
│   ├── transport/
│   │   └── http/
│   │       ├── handler/    # HTTP handlers + DTOs
│   │       ├── middleware/  # Auth + rate limiter
│   │       └── router.go
│   └── usecase/      # Business logic
├── keys/             # RSA key files (not committed)
├── migrations/       # SQL migrations
├── .env.example      # Environment variable reference
├── Dockerfile
└── docker-compose.yml
```

## Running Tests

```bash
go test ./...
```

## Swagger UI

Available at [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html) when `ENV=local`.

Disabled automatically when `ENV=prod`.

To regenerate docs after changing annotations:

```bash
swag init -g cmd/api/main.go
```
