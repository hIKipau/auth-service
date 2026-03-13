package jwt

import (
	"auth-mytierlist/internal/domain"
	"crypto/rsa"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Manager struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Issuer     string
	KeyID      string
}

type Claims struct {
	gjwt.RegisteredClaims
	Role string `json:"role"`
}

func New(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer, keyID string) *Manager {
	return &Manager{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Issuer:     issuer,
		KeyID:      keyID,
	}
}

func (m *Manager) IssueAccessToken(userID uuid.UUID, role domain.Role, ttl time.Duration) (string, error) {
	now := time.Now().UTC()

	claims := Claims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    m.Issuer,
			Subject:   userID.String(),
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Role: string(role),
	}

	token := gjwt.NewWithClaims(gjwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.KeyID

	return token.SignedString(m.PrivateKey)
}

func (m *Manager) ParseAccessToken(tokenString string) (*Claims, error) {
	token, err := gjwt.ParseWithClaims(tokenString, &Claims{}, func(t *gjwt.Token) (any, error) {
		if _, ok := t.Method.(*gjwt.SigningMethodRSA); !ok {
			return nil, gjwt.ErrTokenSignatureInvalid
		}
		return m.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, gjwt.ErrTokenInvalidClaims
	}

	return claims, nil
}
