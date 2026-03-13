package main

import (
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
