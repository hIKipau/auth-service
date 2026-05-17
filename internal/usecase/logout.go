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

	s, err := uc.sessionsRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil
		}
		return err
	}
	if s == nil || s.RevokedAt != nil {
		return nil
	}

	return uc.sessionsRepo.Revoke(ctx, s.ID)
}