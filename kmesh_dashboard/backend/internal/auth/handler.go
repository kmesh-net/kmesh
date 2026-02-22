package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录成功返回
type LoginResponse struct {
	Token  string `json:"token"`
	User   string `json:"user"`
	Role   string `json:"role"`
	Expire int64  `json:"expire"`
}

// MeResponse 当前用户信息
type MeResponse struct {
	User string `json:"user"`
	Role string `json:"role"`
}

func getJWTSecret() string {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		return defaultJWTSecret
	}
	return s
}

// Login 处理 POST /api/auth/login
func Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		role, ok := VerifyUser(req.Username, req.Password)
		if !ok {
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		expire := 24 * time.Hour
		token, err := CreateToken(req.Username, role, getJWTSecret(), expire)
		if err != nil {
			http.Error(w, "failed to create token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(LoginResponse{
			Token:  token,
			User:   req.Username,
			Role:   role,
			Expire: time.Now().Add(expire).Unix(),
		})
	}
}

// Me 处理 GET /api/auth/me，需在认证中间件之后挂载，返回当前用户与角色
func Me() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		username, role := FromContext(r.Context())
		if username == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MeResponse{User: username, Role: role})
	}
}
