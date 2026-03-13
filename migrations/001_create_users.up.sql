CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    login         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UNIQUE уже создаёт индекс, но пусть будет явно для чтения
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_login ON users(login);