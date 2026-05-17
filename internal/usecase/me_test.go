package usecase

import (
	"auth-mytierlist/internal/domain"
	"auth-mytierlist/internal/usecase/mocks"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMe_Success(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	userID := uuid.New()
	u := makeUser("alice")
	u.ID = userID

	usersRepo.EXPECT().GetByID(mock.Anything, userID).Return(u, nil)

	uc := newTestUsecase(mocks.NewSessionsRepository(t), usersRepo, mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	got, err := uc.Me(context.Background(), userID)

	require.NoError(t, err)
	assert.Equal(t, userID, got.ID)
	assert.Equal(t, "alice", got.Login)
}

func TestMe_NilUserID(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Me(context.Background(), uuid.Nil)
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestMe_UserNotFound(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	usersRepo.EXPECT().GetByID(mock.Anything, mock.Anything).Return(nil, domain.ErrUserNotFound)

	uc := newTestUsecase(mocks.NewSessionsRepository(t), usersRepo, mocks.NewPasswordHasher(t), mocks.NewTokenManager(t))
	_, err := uc.Me(context.Background(), uuid.New())
	assert.ErrorIs(t, err, domain.ErrUserNotFound)
}
