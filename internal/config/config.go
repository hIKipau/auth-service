package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Env         string `env:"ENV" env-default:"local"`
	DatabaseURL string `env:"DATABASE_URL" env-required:"true"`

	JWTIssuer         string `env:"JWT_ISSUER" env-default:"auth-mytierlist"`
	JWTKeyID          string `env:"JWT_KEY_ID" env-default:"key-1"`
	JWTPrivateKeyPath string `env:"JWT_PRIVATE_KEY_PATH" env-required:"true"`
	JWTPublicKeyPath  string `env:"JWT_PUBLIC_KEY_PATH" env-required:"true"`

	HTTPAddress string        `env:"HTTP_ADDRESS" env-default:":8080"`
	HTTPTimeout time.Duration `env:"HTTP_TIMEOUT" env-default:"5s"`
	IdleTimeout time.Duration `env:"HTTP_IDLE_TIMEOUT" env-default:"60s"`

	AccessTTL  time.Duration `env:"ACCESS_TTL" env-default:"15m"`
	RefreshTTL time.Duration `env:"REFRESH_TTL" env-default:"720h"` // 30 дней
	BcryptCost int           `env:"BCRYPT_COST" env-default:"10"`
}

func Load() (*Config, error) {

	_ = godotenv.Load()

	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
