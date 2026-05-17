package handler

type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type MeResponse struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Role  string `json:"role"`
}
