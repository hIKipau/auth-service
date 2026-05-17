# auth-service

Lightweight authentication service written in Go. Implements JWT (RS256) access tokens, secure refresh token rotation, PostgreSQL session storage, and a JWKS endpoint for public key distribution across microservices.

## Features

- JWT access tokens signed with RS256 (asymmetric keys)
- Refresh token rotation with PostgreSQL-backed session storage
- JWKS endpoint (`/.well-known/jwks.json`) for token verification by other services
- Bcrypt password hashing
- IP-based rate limiting on auth endpoints
- Swagger UI at `/swagger/index.html`
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
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

### 2. Configure environment

Create a `.env` file in the project root:

```env
ENV=local

DATABASE_URL=postgres://postgres:postgres@localhost:5432/authdb?sslmode=disable

JWT_ISSUER=auth-mytierlist
JWT_KEY_ID=key-1
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem

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

This starts PostgreSQL, runs migrations, and launches the service on port `8080`.

## API Endpoints

Base path: `/api/v1`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/register` | — | Register a new user |
| `POST` | `/auth/login` | — | Login, receive access + refresh tokens |
| `POST` | `/auth/refresh` | — | Rotate refresh token, get new token pair |
| `POST` | `/auth/logout` | — | Invalidate refresh token |
| `GET` | `/auth/me` | Bearer | Get current user info |
| `GET` | `/.well-known/jwks.json` | — | Public key set for RS256 verification |
| `GET` | `/swagger/*` | — | Swagger UI |
| `GET` | `/ready` | — | Readiness probe |

### Example: Register

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"login": "alice", "password": "secret"}'
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ..."
}
```

### Example: Authenticated request

```bash
curl http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

## Project Structure

```
.
├── cmd/api/          # Entry point
├── config/           # (reserved)
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
├── Dockerfile
└── docker-compose.yml
```

## Running Tests

```bash
go test ./...
```

## Swagger UI

After starting the service, open [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html).

To regenerate docs after changing annotations:

```bash
swag init -g cmd/api/main.go
```
