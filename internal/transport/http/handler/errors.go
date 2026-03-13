package handler

import (
	"auth-mytierlist/internal/domain"
	"errors"
)

func httpStatusFromError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		return 400, "invalid input"
	case errors.Is(err, domain.ErrUserAlreadyExists):
		return 409, "user already exists"
	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrSessionNotFound),
		errors.Is(err, domain.ErrRefreshExpired):
		return 401, "unauthorized"
	default:
		return 500, "internal error"
	}
}
