package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"github.com/google/uuid"
	"time"
)

type UsersRepository interface {
	Create(ctx context.Context, u domain.User) (uuid.UUID, error)
	GetByLogin(ctx context.Context, login string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type SessionsRepository interface {
	Create(ctx context.Context, s domain.RefreshSession) (uuid.UUID, error) // sessionID
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshSession, error)
	Revoke(ctx context.Context, sessionID uuid.UUID) error
	Rotate(ctx context.Context, oldSessionID uuid.UUID, newSession domain.RefreshSession) (uuid.UUID, error)
}

type PasswordHasher interface {
	HashPassword(plain string) (string, error)
	CompareHashAndPassword(hash, plain string) bool
}
type TokenManager interface {
	IssueAccessToken(userID uuid.UUID, role domain.Role, ttl time.Duration) (string, error)
}

type AuthTokens struct {
	AccessToken  string
	RefreshToken string
}

// type Clock interface{ Now() time.Time }
type AuthUsecase struct {
	SessionsRepo SessionsRepository
	UsersRepo    UsersRepository

	Hasher       PasswordHasher
	TokenManager TokenManager

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	//	Clock Clock
}

func NewAuthUsecase(s SessionsRepository, u UsersRepository, hasher PasswordHasher, tokenManager TokenManager, accessTTL time.Duration, refreshTTL time.Duration) *AuthUsecase {
	return &AuthUsecase{
		SessionsRepo: s,
		UsersRepo:    u,
		Hasher:       hasher,
		TokenManager: tokenManager,
		AccessTTL:    accessTTL,
		RefreshTTL:   refreshTTL,
	}
}
