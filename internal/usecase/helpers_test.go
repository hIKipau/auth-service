package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRefreshTokenAndHash(t *testing.T) {
	plain1, hash1, err := generateRefreshTokenAndHash()
	require.NoError(t, err)
	assert.NotEmpty(t, plain1)
	assert.NotEmpty(t, hash1)
	assert.NotEqual(t, plain1, hash1)

	plain2, hash2, err := generateRefreshTokenAndHash()
	require.NoError(t, err)

	// every call must produce unique tokens
	assert.NotEqual(t, plain1, plain2)
	assert.NotEqual(t, hash1, hash2)
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	h1 := hashRefreshToken("sometoken")
	h2 := hashRefreshToken("sometoken")
	assert.Equal(t, h1, h2)
}

func TestHashRefreshToken_DifferentInputs(t *testing.T) {
	assert.NotEqual(t, hashRefreshToken("a"), hashRefreshToken("b"))
}

func TestNormalizeLogin(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"Alice", "alice"},
		{"  BOB  ", "bob"},
		{"", ""},
		{"  ", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.expected, normalizeLogin(c.input))
	}
}
