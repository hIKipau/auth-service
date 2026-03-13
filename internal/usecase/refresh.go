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

	oldSession, err := uc.SessionsRepo.GetByTokenHash(ctx, oldHash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			// не раскрываем: "нет сессии" == "невалидно"
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if oldSession == nil {
		return nil, domain.ErrInvalidCredentials
	}

	now := time.Now().UTC()

	// reuse / logout / уже использован
	if oldSession.RevokedAt != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// истёк
	if !now.Before(oldSession.ExpiresAt) {
		return nil, domain.ErrRefreshExpired
	}

	u, err := uc.UsersRepo.GetByID(ctx, oldSession.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrInvalidCredentials
	}

	access, err := uc.TokenManager.IssueAccessToken(u.ID, u.Role, uc.AccessTTL)
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
		ExpiresAt: now.Add(uc.RefreshTTL),
		CreatedAt: now,
	}

	_, err = uc.SessionsRepo.Rotate(ctx, oldSession.ID, newSession)
	if err != nil {
		// Это либо гонка (уже успели ротировать), либо уже revoked
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	return &AuthTokens{AccessToken: access, RefreshToken: newPlain}, nil
}
