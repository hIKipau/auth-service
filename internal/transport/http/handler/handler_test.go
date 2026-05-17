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
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testAccessTTL  = 15 * time.Minute
	testRefreshTTL = 720 * time.Hour
)

func newHandlers(t *testing.T, svc AuthService) *Handlers {
	t.Helper()
	return NewHandlers(svc, testAccessTTL, testRefreshTTL, false)
}

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

func withCookie(r *http.Request, name, value string) *http.Request {
	r.AddCookie(&http.Cookie{Name: name, Value: value})
	return r
}

func withUserID(r *http.Request, id uuid.UUID) *http.Request {
	return r.WithContext(httpmw.WithUserID(r.Context(), id))
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	require.NoError(t, json.NewDecoder(w.Body).Decode(v))
}

func getCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- Login ---

func TestLogin_Handler_Success(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, "alice", "secret").Return(
		&usecase.AuthTokens{AccessToken: "acc", RefreshToken: "ref"}, nil,
	)

	w := httptest.NewRecorder()
	newHandlers(t, svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
		"login": "alice", "password": "secret",
	}))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "acc", getCookie(w, "access_token").Value)
	assert.Equal(t, "ref", getCookie(w, "refresh_token").Value)
	assert.True(t, getCookie(w, "access_token").HttpOnly)
	assert.True(t, getCookie(w, "refresh_token").HttpOnly)
}

func TestLogin_Handler_InvalidCredentials(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidCredentials)

	w := httptest.NewRecorder()
	newHandlers(t, svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
		"login": "x", "password": "y",
	}))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_Handler_EmptyBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	newHandlers(t, handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{bad json}"))
	r.Header.Set("Content-Type", "application/json")
	newHandlers(t, handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_UnknownField(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"login":"a","password":"b","extra":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	newHandlers(t, handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Handler_InternalError(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Login(mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("unexpected db error"))

	w := httptest.NewRecorder()
	newHandlers(t, svc).Login(w, newReq(t, http.MethodPost, "/login", map[string]string{
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
	newHandlers(t, svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
		"login": "bob", "password": "pass",
	}))

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "a", getCookie(w, "access_token").Value)
	assert.Equal(t, "r", getCookie(w, "refresh_token").Value)
}

func TestRegister_Handler_UserAlreadyExists(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Register(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrUserAlreadyExists)

	w := httptest.NewRecorder()
	newHandlers(t, svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
		"login": "dup", "password": "pass",
	}))

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestRegister_Handler_InvalidInput(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Register(mock.Anything, mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidInput)

	w := httptest.NewRecorder()
	newHandlers(t, svc).Register(w, newReq(t, http.MethodPost, "/register", map[string]string{
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

	r := withCookie(newReq(t, http.MethodPost, "/refresh", nil), "refresh_token", "old_ref")
	w := httptest.NewRecorder()
	newHandlers(t, svc).Refresh(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "new_acc", getCookie(w, "access_token").Value)
	assert.Equal(t, "new_ref", getCookie(w, "refresh_token").Value)
}

func TestRefresh_Handler_NoCookie(t *testing.T) {
	w := httptest.NewRecorder()
	newHandlers(t, handlermocks.NewAuthService(t)).Refresh(w, newReq(t, http.MethodPost, "/refresh", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_Handler_Expired(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Refresh(mock.Anything, "tok").Return(nil, domain.ErrRefreshExpired)

	r := withCookie(newReq(t, http.MethodPost, "/refresh", nil), "refresh_token", "tok")
	w := httptest.NewRecorder()
	newHandlers(t, svc).Refresh(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Logout ---

func TestLogout_Handler_Success_Returns204(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Logout(mock.Anything, "ref_tok").Return(nil)

	r := withCookie(newReq(t, http.MethodPost, "/logout", nil), "refresh_token", "ref_tok")
	w := httptest.NewRecorder()
	newHandlers(t, svc).Logout(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, -1, getCookie(w, "access_token").MaxAge)
	assert.Equal(t, -1, getCookie(w, "refresh_token").MaxAge)
}

func TestLogout_Handler_NoCookie(t *testing.T) {
	w := httptest.NewRecorder()
	newHandlers(t, handlermocks.NewAuthService(t)).Logout(w, newReq(t, http.MethodPost, "/logout", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout_Handler_ServiceError(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Logout(mock.Anything, "tok").Return(errors.New("db error"))

	r := withCookie(newReq(t, http.MethodPost, "/logout", nil), "refresh_token", "tok")
	w := httptest.NewRecorder()
	newHandlers(t, svc).Logout(w, r)

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
	newHandlers(t, svc).Me(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp MeResponse
	decodeBody(t, w, &resp)
	assert.Equal(t, userID.String(), resp.ID)
	assert.Equal(t, "alice", resp.Login)
}

func TestMe_Handler_NoUserInContext(t *testing.T) {
	w := httptest.NewRecorder()
	newHandlers(t, handlermocks.NewAuthService(t)).Me(w, newReq(t, http.MethodGet, "/me", nil))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMe_Handler_UserNotFound(t *testing.T) {
	svc := handlermocks.NewAuthService(t)
	svc.EXPECT().Me(mock.Anything, mock.Anything).Return(nil, domain.ErrUserNotFound)

	r := withUserID(newReq(t, http.MethodGet, "/me", nil), uuid.New())
	w := httptest.NewRecorder()
	newHandlers(t, svc).Me(w, r)

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
	newHandlers(t, handlermocks.NewAuthService(t)).Login(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
