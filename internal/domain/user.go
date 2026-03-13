package domain

import (
	"github.com/google/uuid"
	"time"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	Role         Role
	CreatedAt    time.Time
}
