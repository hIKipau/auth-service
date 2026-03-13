package app

import (
	"auth-mytierlist/internal/adapter/postgresql"
	"auth-mytierlist/internal/config"
	bcrypthasher "auth-mytierlist/internal/pkg/security/hasher"
	jwtmanager "auth-mytierlist/internal/pkg/token/jwt"

	httpRouter "auth-mytierlist/internal/transport/http"
	"auth-mytierlist/internal/usecase"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	const op = "internal/app/Run"

	pgsql, err := postgresql.New(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return fmt.Errorf("%s: Failed to connect to database. Error: %s", op, err.Error())
	}
	defer pgsql.Close()

	usersRepo := postgresql.NewUsersRepo(pgsql)
	sessionsRepo := postgresql.NewSessionsRepo(pgsql)

	privateKey, err := jwtmanager.LoadPrivateKeyFromFile(cfg.JWTPrivateKeyPath)
	if err != nil {
		return err
	}

	publicKey, err := jwtmanager.LoadPublicKeyFromFile(cfg.JWTPublicKeyPath)
	if err != nil {
		return err
	}

	tokenManager := jwtmanager.New(
		privateKey,
		publicKey,
		cfg.JWTIssuer,
		cfg.JWTKeyID,
	)

	hasher := bcrypthasher.New(cfg.BcryptCost)

	authUC := usecase.NewAuthUsecase(
		sessionsRepo,
		usersRepo,
		hasher,
		tokenManager,
		cfg.AccessTTL,
		cfg.RefreshTTL,
	)

	router := httpRouter.Router(authUC, publicKey, cfg.JWTKeyID)
	
	srv := &http.Server{
		Addr:         cfg.HTTPAddress,
		Handler:      router,
		ReadTimeout:  cfg.HTTPTimeout,
		WriteTimeout: cfg.HTTPTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", slog.String("err", err.Error()))
		}
	}()

	log.Info("server started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig // ждём здесь сигнала (Ctrl+C или SIGTERM)

	log.Info("Interrupt received, shutting down...")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = srv.Shutdown(ctxShutdown)

	return nil
}
