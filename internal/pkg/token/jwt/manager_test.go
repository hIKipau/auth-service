package jwt

import (
	"auth-mytierlist/internal/domain"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return New(key, &key.PublicKey, "test-issuer", "test-kid")
}

func TestIssueAccessToken_Success(t *testing.T) {
	m := newTestManager(t)
	userID := uuid.New()

	token, err := m.IssueAccessToken(userID, domain.RoleUser, 15*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestParseAccessToken_Success(t *testing.T) {
	m := newTestManager(t)
	userID := uuid.New()

	token, err := m.IssueAccessToken(userID, domain.RoleAdmin, 15*time.Minute)
	require.NoError(t, err)

	claims, err := m.ParseAccessToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.Equal(t, string(domain.RoleAdmin), claims.Role)
	assert.Equal(t, "test-issuer", claims.Issuer)
}

func TestParseAccessToken_Expired(t *testing.T) {
	m := newTestManager(t)
	userID := uuid.New()

	token, err := m.IssueAccessToken(userID, domain.RoleUser, -time.Minute)
	require.NoError(t, err)

	_, err = m.ParseAccessToken(token)
	assert.Error(t, err)
}

func TestParseAccessToken_WrongSigningMethod(t *testing.T) {
	claims := Claims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role: string(domain.RoleUser),
	}
	// sign with HMAC instead of RSA
	token, err := gjwt.NewWithClaims(gjwt.SigningMethodHS256, claims).SignedString([]byte("hmac_secret"))
	require.NoError(t, err)

	m := newTestManager(t)
	_, err = m.ParseAccessToken(token)
	assert.Error(t, err)
}

func TestParseAccessToken_TamperedSignature(t *testing.T) {
	m := newTestManager(t)
	token, err := m.IssueAccessToken(uuid.New(), domain.RoleUser, time.Hour)
	require.NoError(t, err)

	tampered := token[:len(token)-5] + "XXXXX"
	_, err = m.ParseAccessToken(tampered)
	assert.Error(t, err)
}

func TestParseAccessToken_WrongKey(t *testing.T) {
	m1 := newTestManager(t)
	m2 := newTestManager(t) // different key pair

	token, err := m1.IssueAccessToken(uuid.New(), domain.RoleUser, time.Hour)
	require.NoError(t, err)

	_, err = m2.ParseAccessToken(token)
	assert.Error(t, err)
}

func TestIssueAccessToken_KidInHeader(t *testing.T) {
	m := newTestManager(t)
	token, err := m.IssueAccessToken(uuid.New(), domain.RoleUser, time.Hour)
	require.NoError(t, err)

	// parse without validation just to inspect header
	parsed, _, err := new(gjwt.Parser).ParseUnverified(token, &Claims{})
	require.NoError(t, err)
	assert.Equal(t, "test-kid", parsed.Header["kid"])
}
