package domain

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")

	ErrSessionNotFound    = errors.New("session not found")
	ErrRefreshExpired     = errors.New("refresh expired")
	ErrSessionRevoked     = errors.New("session revoked")
	ErrSessionCompromised = errors.New("session compromised")
)
