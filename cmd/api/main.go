// @title           auth-mytierlist API
// @version         1.0
// @description     JWT-based authentication service using RS256 with refresh token rotation.

// @host            localhost:8080
// @BasePath        /api/v1

// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Enter the token with the `Bearer ` prefix, e.g. "Bearer eyJ..."
package main

import (
	_ "auth-mytierlist/docs"
	"auth-mytierlist/internal/app"
	"auth-mytierlist/internal/config"
	"auth-mytierlist/internal/logger"
	"context"
	"log"
	"log/slog"
	"os"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	logger := logger.New(cfg.Env)

	err = app.Run(context.Background(), cfg, logger)
	if err != nil {
		logger.Error("Could not start application", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
