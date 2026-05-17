package http

import (
	"auth-mytierlist/internal/transport/http/handler"
	httpmw "auth-mytierlist/internal/transport/http/middleware"
	"auth-mytierlist/internal/usecase"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	httpSwagger "github.com/swaggo/http-swagger"
)

func Router(service *usecase.AuthUsecase, publicKey *rsa.PublicKey, keyID string, parseToken func(string) (uuid.UUID, error)) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	handlers := handler.NewHandlers(service)
	limiter := httpmw.NewIPRateLimiter(10, time.Minute)

	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/.well-known/jwks.json", handler.JWKSHandler(publicKey, keyID))

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			r.Route("/auth", func(r chi.Router) {
				r.Use(limiter.Middleware())

				r.Post("/login", handlers.Login)
				r.Post("/register", handlers.Register)
				r.Post("/refresh", handlers.Refresh)
				r.Post("/logout", handlers.Logout)

				r.Group(func(r chi.Router) {
					r.Use(httpmw.Auth(parseToken))
					r.Get("/me", handlers.Me)
				})
			})
		})
	})

	return r
}
