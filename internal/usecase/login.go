package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (uc *AuthUsecase) Login(ctx context.Context, login, password string) (*AuthTokens, error) {
	login = normalizeLogin(login)
	if login == "" || password == "" {
		return nil, domain.ErrInvalidInput
	}

	u, err := uc.UsersRepo.GetByLogin(ctx, login)
	if err != nil {
		// не раскрываем детали
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !uc.Hasher.CompareHashAndPassword(u.PasswordHash, password) {
		return nil, domain.ErrInvalidCredentials
	}

	access, err := uc.TokenManager.IssueAccessToken(u.ID, u.Role, uc.AccessTTL)
	if err != nil {
		return nil, err
	}

	refreshPlain, refreshHash, err := generateRefreshTokenAndHash()
	if err != nil {
		return nil, err
	}

	session := domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    u.ID,
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
