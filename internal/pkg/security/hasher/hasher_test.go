package hasher

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_ZeroCost_UsesDefault(t *testing.T) {
	h := New(0)
	assert.Equal(t, bcrypt.DefaultCost, h.Cost)
}

func TestNew_CustomCost(t *testing.T) {
	h := New(bcrypt.MinCost)
	assert.Equal(t, bcrypt.MinCost, h.Cost)
}

func TestHashPassword_ProducesNonEmptyHash(t *testing.T) {
	h := New(bcrypt.MinCost)
	hash, err := h.HashPassword("my_password")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "my_password", hash)
}

func TestHashPassword_SameInputDifferentHash(t *testing.T) {
	h := New(bcrypt.MinCost)
	hash1, err := h.HashPassword("pass")
	require.NoError(t, err)
	hash2, err := h.HashPassword("pass")
	require.NoError(t, err)
	// bcrypt uses random salt — two hashes of the same password are different
	assert.NotEqual(t, hash1, hash2)
}

func TestCompareHashAndPassword_Correct(t *testing.T) {
	h := New(bcrypt.MinCost)
	hash, err := h.HashPassword("secret")
	require.NoError(t, err)
	assert.True(t, h.CompareHashAndPassword(hash, "secret"))
}

func TestCompareHashAndPassword_Wrong(t *testing.T) {
	h := New(bcrypt.MinCost)
	hash, err := h.HashPassword("secret")
	require.NoError(t, err)
	assert.False(t, h.CompareHashAndPassword(hash, "wrong"))
}

func TestCompareHashAndPassword_InvalidHash(t *testing.T) {
	h := New(bcrypt.MinCost)
	assert.False(t, h.CompareHashAndPassword("not_a_bcrypt_hash", "password"))
}
