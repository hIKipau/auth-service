package http

import (
	"auth-mytierlist/internal/transport/http/handler"
	"auth-mytierlist/internal/usecase"
	"crypto/rsa"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"
)

func Router(service *usecase.AuthUsecase, publicKey *rsa.PublicKey, keyID string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	handlers := handler.NewHandlers(service)

	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/.well-known/jwks.json", handler.JWKSHandler(publicKey, keyID))
	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Route("/auth", func(r chi.Router) {
				r.Post("/login", handlers.Login)
				r.Post("/register", handlers.Register)
				r.Get("/me", handlers.Me)
				r.Post("/refresh", handlers.Refresh)
				r.Post("/logout", handlers.Logout)
			})
		})
	})

	return r
}
