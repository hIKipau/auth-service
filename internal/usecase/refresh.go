package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (uc *AuthUsecase) Refresh(ctx context.Context, refreshToken string) (*AuthTokens, error) {
	if refreshToken == "" {
		return nil, domain.ErrInvalidInput
	}

	oldHash := hashRefreshToken(refreshToken)

	oldSession, err := uc.sessionsRepo.GetByTokenHash(ctx, oldHash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if oldSession == nil {
		return nil, domain.ErrInvalidCredentials
	}

	now := time.Now().UTC()

	if oldSession.RevokedAt != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !now.Before(oldSession.ExpiresAt) {
		return nil, domain.ErrRefreshExpired
	}

	u, err := uc.usersRepo.GetByID(ctx, oldSession.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrInvalidCredentials
	}

	access, err := uc.tokenManager.IssueAccessToken(u.ID, u.Role, uc.accessTTL)
	if err != nil {
		return nil, err
	}

	newPlain, newHash, err := generateRefreshTokenAndHash()
	if err != nil {
		return nil, err
	}

	newSession := domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: newHash,
		ExpiresAt: now.Add(uc.refreshTTL),
		CreatedAt: now,
	}

	_, err = uc.sessionsRepo.Rotate(ctx, oldSession.ID, newSession)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	return &AuthTokens{AccessToken: access, RefreshToken: newPlain}, nil
}