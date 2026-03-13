package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"
	"errors"
)

func (uc *AuthUsecase) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return domain.ErrInvalidInput
	}

	tokenHash := hashRefreshToken(refreshToken)

	s, err := uc.SessionsRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			// logout идемпотентный: если уже нет сессии — ок
			return nil
		}
		return err
	}
	if s == nil {
		return nil
	}

	// если уже revoked — тоже ок
	if s.RevokedAt != nil {
		return nil
	}

	// revoke по id
	return uc.SessionsRepo.Revoke(ctx, s.ID)
}
