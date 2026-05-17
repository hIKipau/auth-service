package usecase

import (
	"auth-mytierlist/internal/domain"
	"auth-mytierlist/internal/usecase/mocks"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeUser(login string) *domain.User {
	return &domain.User{
		ID:           uuid.New(),
		Login:        login,
		PasswordHash: "hashed",
		Role:         domain.RoleUser,
	}
}

func TestLogin_Success(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	u := makeUser("alice")
	usersRepo.EXPECT().GetByLogin(mock.Anything, "alice").Return(u, nil)
	hasher.EXPECT().CompareHashAndPassword("hashed", "secret").Return(true)
	tokenMgr.EXPECT().IssueAccessToken(u.ID, domain.RoleUser, mock.Anything).Return("access", nil)
	sessionsRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(s domain.RefreshSession) bool {
		return s.UserID == u.ID
	})).Return(uuid.New(), nil)

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	tokens, err := uc.Login(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "access", tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestLogin_EmptyLogin(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Login(context.Background(), "", "pass")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestLogin_EmptyPassword(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Login(context.Background(), "alice", "")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestLogin_PasswordTooLong(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Login(context.Background(), "alice", string(make([]byte, 73)))
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestLogin_UserNotFound_ReturnsInvalidCredentials(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	hasher := mocks.NewPasswordHasher(t)

	usersRepo.EXPECT().GetByLogin(mock.Anything, mock.Anything).Return(nil, domain.ErrUserNotFound)

	uc := newTestUsecase(mocks.NewSessionsRepository(t), usersRepo, hasher, mocks.NewTokenManager(t))
	_, err := uc.Login(context.Background(), "ghost", "pass")
	// must NOT leak ErrUserNotFound to caller
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	assert.NotErrorIs(t, err, domain.ErrUserNotFound)
}

func TestLogin_WrongPassword(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	hasher := mocks.NewPasswordHasher(t)

	u := makeUser("alice")
	usersRepo.EXPECT().GetByLogin(mock.Anything, "alice").Return(u, nil)
	hasher.EXPECT().CompareHashAndPassword("hashed", "wrong").Return(false)

	uc := newTestUsecase(mocks.NewSessionsRepository(t), usersRepo, hasher, mocks.NewTokenManager(t))
	_, err := uc.Login(context.Background(), "alice", "wrong")
	assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestLogin_RepoError(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	usersRepo.EXPECT().GetByLogin(mock.Anything, mock.Anything).Return(nil, errors.New("db down"))

	uc := newTestUsecase(
		mocks.NewSessionsRepository(t), usersRepo,
		mocks.NewPasswordHasher(t), mocks.NewTokenManager(t),
	)
	_, err := uc.Login(context.Background(), "alice", "pass")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, domain.ErrInvalidCredentials)
}

func TestLogin_SessionCreateError(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	u := makeUser("alice")
	usersRepo.EXPECT().GetByLogin(mock.Anything, mock.Anything).Return(u, nil)
	hasher.EXPECT().CompareHashAndPassword(mock.Anything, mock.Anything).Return(true)
	tokenMgr.EXPECT().IssueAccessToken(mock.Anything, mock.Anything, mock.Anything).Return("tok", nil)
	sessionsRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(uuid.Nil, errors.New("db error"))

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Login(context.Background(), "alice", "pass")
	assert.Error(t, err)
}
