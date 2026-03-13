package postgresql

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UsersRepo struct {
	db *pgxpool.Pool
}

func NewUsersRepo(p *PostgreSQL) *UsersRepo {
	return &UsersRepo{db: p.db}
}

func (r *UsersRepo) GetByLogin(ctx context.Context, login string) (*domain.User, error) {
	login = strings.TrimSpace(login)
	if login == "" {
		return nil, domain.ErrInvalidInput
	}

	var u domain.User
	err := r.db.QueryRow(ctx, `
		SELECT id, login, password_hash, role, created_at
		FROM users
		WHERE login = $1
	`, login).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return &u, nil
}

func (r *UsersRepo) Create(ctx context.Context, u domain.User) (uuid.UUID, error) {
	u.Login = strings.TrimSpace(u.Login)
	if u.Login == "" || u.PasswordHash == "" {
		return uuid.Nil, domain.ErrInvalidInput
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New() //UUID генерим в Go
	}
	if u.Role == "" {
		u.Role = domain.RoleUser
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}

	_, err := r.db.Exec(ctx, `
		INSERT INTO users (id, login, password_hash, role, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, u.ID, u.Login, u.PasswordHash, u.Role, u.CreatedAt)

	if err != nil {
		// unique violation на login
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return uuid.Nil, domain.ErrUserAlreadyExists
		}
		return uuid.Nil, err
	}

	return u.ID, nil
}

func (r *UsersRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if id == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}

	var u domain.User
	err := r.db.QueryRow(ctx, `
		SELECT id, login, password_hash, role, created_at
		FROM users
		WHERE id = $1
	`, id).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role, &u.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return &u, nil
}
