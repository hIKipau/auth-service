package handler

import (
	"auth-mytierlist/internal/domain"
	handlermocks "auth-mytierlist/internal/transport/http/handler/mocks"
	httpmw "auth-mytierlist/internal/transport/http/middleware"
	"auth-mytierlist/internal/usecase"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newReq(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	if body == nil {
		return httptest.NewRequest(method, path, nil)
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func withUserID(r *http.Request, id uuid.UUID) *http.Request {
	return r.WithContext(httpmw.WithUserID(r.Context(), id))
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(w.Body).Decode(v))
}

// --- Login ---

func TestLogin_Handler_Success(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, "alice", "secret").Return(
		&usecase.AuthTokens{AccessToken: "acc", RefreshToken: "ref"}, nil,
	)

	w := httptest.NewRecorder()
	NewHandlers(svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
		"login": "alice", "password": "secret",
	}))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp TokensResponse
	decodeBody(t, w, &resp)
	assert.Equal(t, "acc", resp.AccessToken)
	assert.Equal(t, "ref", resp.RefreshToken)
}

func TestLogin_Handler_InvalidCredentials(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidCredentials)

	w := httptest.NewRecorder()
	NewHandlers(svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
		"login": "x", "password": "y",
	}))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_Handler_EmptyBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	NewHandlers(handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{bad json}"))
	r.Header.Set("Content-Type", "application/json")
	NewHandlers(handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_UnknownField(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"login":"a","password":"b","extra":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	NewHandlers(handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_InternalError(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("unexpected db error"))

	w := httptest.NewRecorder()
	NewHandlers(svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
		"login": "a", "password": "b",
	}))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Register ---

func TestRegister_Handler_Success_Returns201(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Register(mock.Anything, "bob", "pass").Return(
		&usecase.AuthTokens{AccessToken: "a", RefreshToken: "r"}, nil,
	)

	w := httptest.NewRecorder()
	NewHandlers(svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
		"login": "bob", "password": "pass",
	}))

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRegister_Handler_UserAlreadyExists(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Register(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrUserAlreadyExists)

	w := httptest.NewRecorder()
	NewHandlers(svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
		"login": "dup", "password": "pass",
	}))

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestRegister_Handler_InvalidInput(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Register(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidInput)

	w := httptest.NewRecorder()
	NewHandlers(svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
		"login": "", "password": "",
	}))

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Refresh ---

func TestRefresh_Handler_Success(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Refresh(mock.Anything, "old_ref").Return(
		&usecase.AuthTokens{AccessToken: "new_acc", RefreshToken: "new_ref"}, nil,
	)

	w := httptest.NewRecorder()
	NewHandlers(svc).Refresh(w, newReq(t, http.MethodPost, "/refresh", map[string]string{
		"refresh_token": "old_ref",
	}))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp TokensResponse
	decodeBody(t, w, &resp)
	assert.Equal(t, "new_acc", resp.AccessToken)
}

func TestRefresh_Handler_Expired(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Refresh(mock.Anything, mock.Anything).Return(nil, domain.ErrRefreshExpired)

	w := httptest.NewRecorder()
	NewHandlers(svc).Refresh(w, newReq(t, http.MethodPost, "/refresh", map[string]string{
		"refresh_token": "tok",
	}))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Logout ---

func TestLogout_Handler_Success_Returns204(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Logout(mock.Anything, "ref_tok").Return(nil)

	w := httptest.NewRecorder()
	NewHandlers(svc).Logout(w, newReq(t, http.MethodPost, "/logout", map[string]string{
		"refresh_token": "ref_tok",
	}))

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestLogout_Handler_ServiceError(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Logout(mock.Anything, mock.Anything).Return(errors.New("db error"))

	w := httptest.NewRecorder()
	NewHandlers(svc).Logout(w, newReq(t, http.MethodPost, "/logout", map[string]string{
		"refresh_token": "tok",
	}))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Me ---

func TestMe_Handler_Success(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	userID := uuid.New()
	svc.EXPECT().Me(mock.Anything, userID).Return(&domain.User{
		ID: userID, Login: "alice", Role: domain.RoleUser,
	}, nil)

	r := withUserID(newReq(t, http.MethodGet, "/me", nil), userID)
	w := httptest.NewRecorder()
	NewHandlers(svc).Me(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp MeResponse
	decodeBody(t, w, &resp)
	assert.Equal(t, userID.String(), resp.ID)
	assert.Equal(t, "alice", resp.Login)
}

func TestMe_Handler_NoUserInContext(t *testing.T) {
	w := httptest.NewRecorder()
	NewHandlers(handlermocks.NewAuthService(t)).Me(w, newReq(t, http.MethodGet, "/me", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMe_Handler_UserNotFound(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Me(mock.Anything, mock.Anything).Return(nil, domain.ErrUserNotFound)

	r := withUserID(newReq(t, http.MethodGet, "/me", nil), uuid.New())
	w := httptest.NewRecorder()
	NewHandlers(svc).Me(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- JWKS ---

func TestJWKS_Handler(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	JWKSHandler(&key.PublicKey, "key-1")(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Cache-Control"), "max-age")

	var body map[string]any
	decodeBody(t, w, &body)
	keys, ok := body["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)
	keyMap := keys[0].(map[string]any)
	assert.Equal(t, "RSA", keyMap["kty"])
	assert.Equal(t, "key-1", keyMap["kid"])
}

// --- Body size limit ---

func TestDecodeJSON_OversizedBody(t *testing.T) {
	big := strings.Repeat("x", 2<<20)
	body := `{"login":"` + big + `","password":"p"}`
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	NewHandlers(handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
