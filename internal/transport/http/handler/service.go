package handler

import (
	"auth-mytierlist/internal/domain"
	"auth-mytierlist/internal/usecase"
	"context"

	"github.com/google/uuid"
)

type AuthService interface {
	Login(ctx context.Context, login, password string) (*usecase.AuthTokens, error)
	Register(ctx context.Context, login, password string) (*usecase.AuthTokens, error)
	Refresh(ctx context.Context, refreshToken string) (*usecase.AuthTokens, error)
	Logout(ctx context.Context, refreshToken string) error
	Me(ctx context.Context, userID uuid.UUID) (*domain.User, error)
}
