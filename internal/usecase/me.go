package usecase

import (
	"auth-mytierlist/internal/domain"
	"context"

	"github.com/google/uuid"
)

func (uc *AuthUsecase) Me(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrInvalidInput
	}
	return uc.UsersRepo.GetByID(ctx, userID)
}
