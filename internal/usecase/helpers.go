package usecase

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func generateRefreshTokenAndHash() (plain string, hash string, err error) {
	b := make([]byte, 32) // 256-bit
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plain = base64.RawURLEncoding.EncodeToString(b)
	hash = hashRefreshToken(plain)
	return plain, hash, nil
}

func hashRefreshToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
