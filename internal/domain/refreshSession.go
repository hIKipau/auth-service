package domain

import (
	"github.com/google/uuid"
	"time"
)

type RefreshSession struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TokenHash    string
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	ReplacedByID *uuid.UUID
	CreatedAt    time.Time
}
