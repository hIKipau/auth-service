package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (uc *AuthUsecase) Register(ctx context.Context, login, password string) (*AuthTokens, error) {
	login = normalizeLogin(login)
	if login == "" || password == "" || len(password) > 72 {
		return nil, domain.ErrInvalidInput
	}

	hash, err := uc.hasher.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := domain.User{
		ID:           uuid.New(),
		Login:        login,
		PasswordHash: hash,
		Role:         domain.RoleUser,
		CreatedAt:    time.Now().UTC(),
	}

	userID, err := uc.usersRepo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	access, err := uc.tokenManager.IssueAccessToken(userID, user.Role, uc.accessTTL)
	if err != nil {
		return nil, err
	}

	refreshPlain, refreshHash, err := generateRefreshTokenAndHash()
	if err != nil {
		return nil, err
	}

	session := domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: refreshHash,
		ExpiresAt: time.Now().UTC().Add(uc.refreshTTL),
		CreatedAt: time.Now().UTC(),
	}

	_, err = uc.sessionsRepo.Create(ctx, session)
	if err != nil {
		return nil, err
	}

	return &AuthTokens{AccessToken: access, RefreshToken: refreshPlain}, nil
}

func normalizeLogin(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}