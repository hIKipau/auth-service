package handler

import (
	"auth-mytierlist/internal/domain"
	httpmw "auth-mytierlist/internal/transport/http/middleware"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
)

type Handlers struct {
	uc AuthService
}

func NewHandlers(service AuthService) *Handlers {
	return &Handlers{uc: service}
}

// Login godoc
// @Summary      Login
// @Description  Authenticate with login and password, receive access + refresh tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      LoginRequest   true  "Credentials"
// @Success      200      {object}  TokensResponse
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse
// @Failure      429      {object}  ErrorResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /auth/login [post]
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

// JWKSHandler godoc
// @Summary      JSON Web Key Set
// @Description  Returns the RSA public key set used to verify access tokens (RS256)
// @Tags         auth
// @Produce      json
// @Success      200  {object}  object{keys=[]object{kty=string,use=string,alg=string,kid=string,n=string,e=string}}
// @Router       /.well-known/jwks.json [get]
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
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Register godoc
// @Summary      Register
// @Description  Create a new user account; returns access + refresh tokens on success
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterRequest  true  "Registration data"
// @Success      201      {object}  TokensResponse
// @Failure      400      {object}  ErrorResponse
// @Failure      409      {object}  ErrorResponse  "Login already taken"
// @Failure      429      {object}  ErrorResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /auth/register [post]
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

	writeJSON(w, http.StatusCreated, TokensResponse{
		AccessToken:  toks.AccessToken,
		RefreshToken: toks.RefreshToken,
	})
}

// Refresh godoc
// @Summary      Refresh tokens
// @Description  Exchange a valid refresh token for a new access + refresh token pair (rotation)
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      RefreshRequest  true  "Refresh token"
// @Success      200      {object}  TokensResponse
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse  "Token invalid, expired, or already used"
// @Failure      429      {object}  ErrorResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /auth/refresh [post]
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

// Logout godoc
// @Summary      Logout
// @Description  Revoke the provided refresh token; idempotent — safe to call even if already logged out
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  LogoutRequest  true  "Refresh token to revoke"
// @Success      204      "No Content"
// @Failure      400      {object}  ErrorResponse
// @Failure      429      {object}  ErrorResponse
// @Failure      500      {object}  ErrorResponse
// @Router       /auth/logout [post]
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if err := h.uc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeDomainError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Me godoc
// @Summary      Get current user
// @Description  Returns profile of the authenticated user
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MeResponse
// @Failure      401  {object}  ErrorResponse  "Missing or invalid access token"
// @Failure      429  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Router       /auth/me [get]
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpmw.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
