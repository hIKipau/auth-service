package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (uc *AuthUsecase) Register(ctx context.Context, login, password string) (*AuthTokens, error) {
	login = normalizeLogin(login)
	if login == "" || password == "" {
		return nil, domain.ErrInvalidInput
	}

	// Можно без этого pre-check (уникальность ловится в repo),
	// но так можно вернуть красивый ErrUserAlreadyExists до INSERT.
	if u, err := uc.UsersRepo.GetByLogin(ctx, login); err == nil && u != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	hash, err := uc.Hasher.HashPassword(password)
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

	userID, err := uc.UsersRepo.Create(ctx, user)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			return nil, err
		}
		return nil, err
	}

	access, err := uc.TokenManager.IssueAccessToken(userID, user.Role, uc.AccessTTL)
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
		ExpiresAt: time.Now().UTC().Add(uc.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}

	_, err = uc.SessionsRepo.Create(ctx, session)
	if err != nil {
		return nil, err
	}

	return &AuthTokens{AccessToken: access, RefreshToken: refreshPlain}, nil
}

func normalizeLogin(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
