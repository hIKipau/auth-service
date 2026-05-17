package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func rateLimitedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func makeRequest(mw func(http.Handler) http.Handler, ip string) int {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":12345"
	w := httptest.NewRecorder()
	mw(rateLimitedHandler()).ServeHTTP(w, r)
	return w.Code
}

func TestRateLimiter_AllowsRequestsUnderLimit(t *testing.T) {
	rl := NewIPRateLimiter(5, time.Minute)
	mw := rl.Middleware()

	for i := 0; i < 5; i++ {
		code := makeRequest(mw, "10.0.0.1")
		assert.Equal(t, http.StatusOK, code, "request %d should pass", i+1)
	}
}

func TestRateLimiter_BlocksRequestsOverLimit(t *testing.T) {
	rl := NewIPRateLimiter(3, time.Minute)
	mw := rl.Middleware()

	for i := 0; i < 3; i++ {
		makeRequest(mw, "10.0.0.2")
	}
	code := makeRequest(mw, "10.0.0.2")
	assert.Equal(t, http.StatusTooManyRequests, code)
}

func TestRateLimiter_DifferentIPsAreIndependent(t *testing.T) {
	rl := NewIPRateLimiter(1, time.Minute)
	mw := rl.Middleware()

	assert.Equal(t, http.StatusOK, makeRequest(mw, "1.1.1.1"))
	assert.Equal(t, http.StatusTooManyRequests, makeRequest(mw, "1.1.1.1"))

	// different IP must still get through
	assert.Equal(t, http.StatusOK, makeRequest(mw, "2.2.2.2"))
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := NewIPRateLimiter(1, 50*time.Millisecond)
	mw := rl.Middleware()

	assert.Equal(t, http.StatusOK, makeRequest(mw, "3.3.3.3"))
	assert.Equal(t, http.StatusTooManyRequests, makeRequest(mw, "3.3.3.3"))

	time.Sleep(60 * time.Millisecond)

	assert.Equal(t, http.StatusOK, makeRequest(mw, "3.3.3.3"))
}
