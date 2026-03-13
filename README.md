# auth-service
Lightweight authentication service written in Go. Implements JWT (RS256) access tokens, secure refresh token rotation, PostgreSQL session storage, and JWKS endpoint for public key distribution across microservices.

You can create PRIVATE and PUBLIC key with:

    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout -out public.pem

Then you can start service with:
    
    docker compose up --build

