package postgresql

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionsRepo struct {
	db *pgxpool.Pool
}

func NewSessionsRepo(p *PostgreSQL) *SessionsRepo {
	return &SessionsRepo{db: p.db}
}

func (r *SessionsRepo) Create(ctx context.Context, s domain.RefreshSession) (uuid.UUID, error) {
	// Генерим ID в Go, если не задан
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.UserID == uuid.Nil {
		return uuid.Nil, domain.ErrInvalidInput
	}
	if s.TokenHash == "" {
		return uuid.Nil, domain.ErrInvalidInput
	}
	if s.ExpiresAt.IsZero() {
		return uuid.Nil, domain.ErrInvalidInput
	}

	// created_at ставит БД
	_, err := r.db.Exec(ctx, `
		INSERT INTO refresh_sessions (id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
	`, s.ID, s.UserID, s.TokenHash, s.ExpiresAt, s.RevokedAt, s.ReplacedByID)
	if err != nil {
		return uuid.Nil, err
	}

	return s.ID, nil
}

func (r *SessionsRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshSession, error) {
	if tokenHash == "" {
		return nil, domain.ErrInvalidInput
	}

	var s domain.RefreshSession

	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at
		FROM refresh_sessions
		WHERE token_hash = $1
	`, tokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.ExpiresAt,
		&s.RevokedAt,    // pgx умеет сканить NULL в *time.Time
		&s.ReplacedByID, // и NULL в *uuid.UUID
		&s.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrSessionNotFound
		}
		return nil, err
	}

	return &s, nil
}

func (r *SessionsRepo) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return domain.ErrInvalidInput
	}

	cmd, err := r.db.Exec(ctx, `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL
	`, sessionID)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}

	return nil
}

func (r *SessionsRepo) Rotate(ctx context.Context, oldSessionID uuid.UUID, newSession domain.RefreshSession) (uuid.UUID, error) {
	if oldSessionID == uuid.Nil {
		return uuid.Nil, domain.ErrInvalidInput
	}

	// newSession: обязателен минимум user_id, token_hash, expires_at
	if newSession.ID == uuid.Nil {
		newSession.ID = uuid.New()
	}
	if newSession.UserID == uuid.Nil || newSession.TokenHash == "" || newSession.ExpiresAt.IsZero() {
		return uuid.Nil, domain.ErrInvalidInput
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	// Отозвать старую сессию ТОЛЬКО если она ещё активна
	cmd, err := tx.Exec(ctx, `
		UPDATE refresh_sessions
		SET revoked_at = now()
		WHERE id = $1
		  AND revoked_at IS NULL
	`, oldSessionID)
	if err != nil {
		return uuid.Nil, err
	}
	if cmd.RowsAffected() == 0 {
		return uuid.Nil, domain.ErrSessionNotFound
	}

	//  Создать новую сессию
	_, err = tx.Exec(ctx, `
		INSERT INTO refresh_sessions (id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at)
		VALUES ($1, $2, $3, $4, NULL, NULL, now())
	`, newSession.ID, newSession.UserID, newSession.TokenHash, newSession.ExpiresAt)
	if err != nil {
		return uuid.Nil, err
	}

	//  Связать старую -> новую
	_, err = tx.Exec(ctx, `
		UPDATE refresh_sessions
		SET replaced_by_id = $2
		WHERE id = $1
	`, oldSessionID, newSession.ID)
	if err != nil {
		return uuid.Nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}

	return newSession.ID, nil
}
