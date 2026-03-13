package handler

import (
	"auth-mytierlist/internal/domain"
	"auth-mytierlist/internal/usecase"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type Handlers struct {
	uc *usecase.AuthUsecase
}

func NewHandlers(service *usecase.AuthUsecase) *Handlers {
	return &Handlers{uc: service}
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	toks, err := h.uc.Login(r.Context(), req.Login, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokensResponse{
		AccessToken:  toks.AccessToken,
		RefreshToken: toks.RefreshToken,
	})
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func base64URLUInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func JWKSHandler(publicKey *rsa.PublicKey, kid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := jwks{
			Keys: []jwk{
				{
					Kty: "RSA",
					Use: "sig",
					Alg: "RS256",
					Kid: kid,
					N:   base64URLUInt(publicKey.N),
					E:   base64URLUInt(big.NewInt(int64(publicKey.E))),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	toks, err := h.uc.Register(r.Context(), req.Login, req.Password)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokensResponse{
		AccessToken:  toks.AccessToken,
		RefreshToken: toks.RefreshToken,
	})
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	toks, err := h.uc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokensResponse{
		AccessToken:  toks.AccessToken,
		RefreshToken: toks.RefreshToken,
	})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.uc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeDomainError(w, err)
		return
	}

	// Идемпотентный logout обычно 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	// Правильно: userID должен ставить auth middleware после проверки access token.
	// Пока middleware нет — временно возьмём X-User-ID.
	// Заменишь на context value, когда сделаешь middleware.
	userIDStr := strings.TrimSpace(r.Header.Get("X-User-ID"))
	if userIDStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid user id"}`, http.StatusBadRequest)
		return
	}

	u, err := h.uc.Me(r.Context(), userID)
	if err != nil {
		writeDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, MeResponse{
		ID:    u.ID.String(),
		Login: u.Login,
		Role:  string(u.Role),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		http.Error(w, `{"error":"empty body"}`, http.StatusBadRequest)
		return errors.New("empty body")
	}
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return err
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return errors.New("extra json tokens")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid input")

	case errors.Is(err, domain.ErrUserAlreadyExists):
		writeError(w, http.StatusConflict, "user already exists")

	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrSessionNotFound),
		errors.Is(err, domain.ErrRefreshExpired),
		errors.Is(err, domain.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, "unauthorized")

	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
	})
}
