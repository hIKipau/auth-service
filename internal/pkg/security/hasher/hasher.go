package hasher

import "golang.org/x/crypto/bcrypt"

type Hasher struct {
	Cost int
}

func New(cost int) Hasher {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return Hasher{Cost: cost}
}

func (h Hasher) HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), h.Cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (h Hasher) CompareHashAndPassword(hash string, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
