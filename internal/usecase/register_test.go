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

func newTestUsecase(
	sessionsRepo *mocks.SessionsRepository,
	usersRepo *mocks.UsersRepository,
	hasher *mocks.PasswordHasher,
	tokenMgr *mocks.TokenManager,
) *AuthUsecase {
	return NewAuthUsecase(sessionsRepo, usersRepo, hasher, tokenMgr, 15*time.Minute, 30*24*time.Hour)
}

func TestRegister_Success(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()

	hasher.EXPECT().HashPassword("secret").Return("hashed", nil)
	usersRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u domain.User) bool {
		return u.Login == "alice" && u.Role == domain.RoleUser && u.PasswordHash == "hashed"
	})).Return(userID, nil)
	tokenMgr.EXPECT().IssueAccessToken(userID, domain.RoleUser, 15*time.Minute).Return("access_tok", nil)
	sessionsRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(s domain.RefreshSession) bool {
		return s.UserID == userID && s.TokenHash != ""
	})).Return(uuid.New(), nil)

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	tokens, err := uc.Register(context.Background(), "alice", "secret")

	require.NoError(t, err)
	assert.Equal(t, "access_tok", tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
}

func TestRegister_NormalizesLogin(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()
	hasher.EXPECT().HashPassword(mock.Anything).Return("h", nil)
	usersRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u domain.User) bool {
		return u.Login == "alice"
	})).Return(userID, nil)
	tokenMgr.EXPECT().IssueAccessToken(mock.Anything, mock.Anything, mock.Anything).Return("tok", nil)
	sessionsRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(uuid.New(), nil)

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Register(context.Background(), "  ALICE  ", "password")
	require.NoError(t, err)
}

func TestRegister_EmptyLogin(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Register(context.Background(), "", "password")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestRegister_EmptyPassword(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	_, err := uc.Register(context.Background(), "alice", "")
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestRegister_PasswordTooLong(t *testing.T) {
	uc := newTestUsecase(
		mocks.NewSessionsRepository(t),
		mocks.NewUsersRepository(t),
		mocks.NewPasswordHasher(t),
		mocks.NewTokenManager(t),
	)
	long := string(make([]byte, 73))
	_, err := uc.Register(context.Background(), "alice", long)
	assert.ErrorIs(t, err, domain.ErrInvalidInput)
}

func TestRegister_HasherError(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	hasher.EXPECT().HashPassword(mock.Anything).Return("", errors.New("bcrypt error"))

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Register(context.Background(), "alice", "password")
	assert.Error(t, err)
}

func TestRegister_UserAlreadyExists(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	hasher.EXPECT().HashPassword(mock.Anything).Return("hash", nil)
	usersRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(uuid.Nil, domain.ErrUserAlreadyExists)

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Register(context.Background(), "alice", "password")
	assert.ErrorIs(t, err, domain.ErrUserAlreadyExists)
}

func TestRegister_TokenIssueError(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()
	hasher.EXPECT().HashPassword(mock.Anything).Return("hash", nil)
	usersRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(userID, nil)
	tokenMgr.EXPECT().IssueAccessToken(mock.Anything, mock.Anything, mock.Anything).Return("", errors.New("key error"))

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Register(context.Background(), "alice", "password")
	assert.Error(t, err)
}

func TestRegister_SessionCreateError(t *testing.T) {
	usersRepo := mocks.NewUsersRepository(t)
	sessionsRepo := mocks.NewSessionsRepository(t)
	hasher := mocks.NewPasswordHasher(t)
	tokenMgr := mocks.NewTokenManager(t)

	userID := uuid.New()
	hasher.EXPECT().HashPassword(mock.Anything).Return("hash", nil)
	usersRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(userID, nil)
	tokenMgr.EXPECT().IssueAccessToken(mock.Anything, mock.Anything, mock.Anything).Return("access", nil)
	sessionsRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(uuid.Nil, errors.New("db error"))

	uc := newTestUsecase(sessionsRepo, usersRepo, hasher, tokenMgr)
	_, err := uc.Register(context.Background(), "alice", "password")
	assert.Error(t, err)
}
