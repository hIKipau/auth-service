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
	"github.com/stretchr/testify/require"
)

func activeSession(userID uuid.UUID) *domain.RefreshSession {
	return &domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: "",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func TestRefresh_EmptyToken(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Refresh(context.Background(), "")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestRefresh_SessionNotFound(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(nil, domain.ErrSessionNotFound)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Refresh(context.Background(), "sometoken")
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestRefresh_SessionRevoked(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)

	revokedAt := time.Now().UTC()
	sess := &domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		RevokedAt: &revokedAt,
	}
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Refresh(context.Background(), "tok")
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestRefresh_SessionExpired(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)

	sess := &domain.RefreshSession{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Refresh(context.Background(), "tok")
	assert.ErrorIs(t, err, domain.ErrRefreshExpired)
}

func TestRefresh_UserNotFound(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	usersRepo := mocks.NewUsersRepository(t)

	userID := uuid.New()
	sess := activeSession(userID)
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)
	usersRepo.EXPECT().GetByID(mock.Anything, userID).Return(nil, domain.ErrUserNotFound)

	uc := newTestUsecase(sessionsRepo, usersRepo, mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Refresh(context.Background(), "tok")
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestRefresh_Success(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	usersRepo := mocks.NewUsersRepository(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()
	sess := activeSession(userID)
	u := makeUser("alice")
	u.ID = userID

	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)
	usersRepo.EXPECT().GetByID(mock.Anything, userID).Return(u, nil)
	tokenMgr.EXPECT().IssueAccessToken(userID, domain.RoleUser, mock.Anything).Return("new_access", nil)
	sessionsRepo.EXPECT().Rotate(mock.Anything, sess.ID, mock.MatchedBy(func(s domain.RefreshSession) bool {
		return s.UserID == userID && s.TokenHash != ""
	})).Return(uuid.New(), nil)

	uc := newTestUsecase(sessionsRepo, usersRepo, mocks.NewPasswordHasher(t), tokenMgr)
	tokens, err := uc.Refresh(context.Background(), "old_plain_token")

	require.NoError(t, err)
	assert.Equal(t, "new_access", tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestRefresh_RotateRaceCondition(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	usersRepo := mocks.NewUsersRepository(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()
	sess := activeSession(userID)
	u := makeUser("alice")
	u.ID = userID

	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(sess, nil)
	usersRepo.EXPECT().GetByID(mock.Anything, userID).Return(u, nil)
	tokenMgr.EXPECT().IssueAccessToken(mock.Anything, mock.Anything, mock.Anything).Return("tok", nil)
	sessionsRepo.EXPECT().Rotate(mock.Anything, mock.Anything, mock.Anything).Return(uuid.Nil, domain.ErrSessionNotFound)

	uc := newTestUsecase(sessionsRepo, usersRepo, mocks.NewPasswordHasher(t), tokenMgr)
	_, err := uc.Refresh(context.Background(), "tok")
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestRefresh_RepoError(t *testing.T) {
	sessionsRepo := mocks.NewSessionsRepository(t)
	sessionsRepo.EXPECT().GetByTokenHash(mock.Anything, mock.Anything).Return(nil, errors.New("db down"))

	uc := newTestUsecase(sessionsRepo, mocks.NewUsersRepository(t), mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Refresh(context.Background(), "tok")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, domain.ErrInvalidCredentials)
}
