package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func okHandler(t *testing.T, expectedID uuid.UUID) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := UserIDFromContext(r.Context())
		require.True(t, ok)
		assert.Equal(t, expectedID, id)
		w.WriteHeader(http.StatusOK)
	})
}

func makeParseToken(id uuid.UUID, err error) func(string) (uuid.UUID, error) {
	return func(_ string) (uuid.UUID, error) { return id, err }
}

func withAccessCookie(r *http.Request, value string) *http.Request {
	r.AddCookie(&http.Cookie{Name: "access_token", Value: value})
	return r
}

func TestAuth_Success(t *testing.T) {
	userID := uuid.New()
	mw := Auth(makeParseToken(userID, nil))

	r := withAccessCookie(httptest.NewRequest(http.MethodGet, "/", nil), "valid_token")
	w := httptest.NewRecorder()

	mw(okHandler(t, userID)).ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuth_MissingCookie(t *testing.T) {
	mw := Auth(makeParseToken(uuid.Nil, nil))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be called")
	})).ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_InvalidToken(t *testing.T) {
	mw := Auth(makeParseToken(uuid.Nil, assert.AnError))

	r := withAccessCookie(httptest.NewRequest(http.MethodGet, "/", nil), "bad_token")
	w := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be called")
	})).ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_SetsContextValue(t *testing.T) {
	userID := uuid.New()
	mw := Auth(makeParseToken(userID, nil))

	var gotID uuid.UUID
	r := withAccessCookie(httptest.NewRequest(http.MethodGet, "/", nil), "tok")
	w := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := UserIDFromContext(r.Context())
		require.True(t, ok)
		gotID = id
	})).ServeHTTP(w, r)

	assert.Equal(t, userID, gotID)
}

func TestWithUserID(t *testing.T) {
	userID := uuid.New()
	ctx := WithUserID(t.Context(), userID)
	got, ok := UserIDFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, userID, got)
}

func TestUserIDFromContext_MissingKey(t *testing.T) {
	_, ok := UserIDFromContext(t.Context())
	assert.False(t, ok)
}
