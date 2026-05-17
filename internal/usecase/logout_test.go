package usecase

import (
	"auth-mytierlist/internal/domain"
	"auth-mytierlist/internal/usecase/mocks"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLogout_EmptyToken(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	err := uc.Logout(context.Background(), "")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestLogout_SessionNotFound_IsIdempotent(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(nil, domain.ErrSessionNotFound)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	err := uc.Logout(context.Background(), "unknown_token")
	assert.NoError(t, err)
}

func TestLogout_AlreadyRevoked_IsIdempotent(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	revokedAt := time.Now()
	sess := &domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		RevokedAt: &revokedAt,
	}
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	err := uc.Logout(context.Background(), "already_revoked_token")
	assert.NoError(t, err)
}

func TestLogout_Success(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	sessID := uuid.New()
	sess := &domain.RefreshSession{
		ID:        sessID,
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)
	sessionsRepo.EXPECT().Revoke(mock.Anything, sessID).Return(nil)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	err := uc.Logout(context.Background(), "valid_token")
	assert.NoError(t, err)
}

func TestLogout_RevokeError(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	sess := &domain.RefreshSession{
		ID:        uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)
	sessionsRepo.EXPECT().Revoke(mock.Anything, mock.Anything).Return(errors.New("db error"))

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	err := uc.Logout(context.Background(), "tok")
	assert.Error(t, err)
}
