CREATE TABLE IF NOT EXISTS refresh_sessions (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ NULL,
    replaced_by_id  UUID NULL REFERENCES refresh_sessions(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_sessions_token_hash
    ON refresh_sessions(token_hash);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user_id
    ON refresh_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_expires_at
    ON refresh_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_active_user
    ON refresh_sessions(user_id)
    WHERE revoked_at IS NULL;