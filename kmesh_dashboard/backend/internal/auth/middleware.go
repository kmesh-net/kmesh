package auth

import (
	"net/http"
	"strings"
)

// routePermission 将 path 与 method 映射为 resource、action（用于 Casbin）
func routePermission(path, method string) (resource, action string, needAuth bool) {
	if !strings.HasPrefix(path, "/api/") {
		return "", "", false
	}
	path = strings.TrimPrefix(path, "/api/")
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")

	// 白名单：无需认证
	if path == "auth/login" || path == "health" || path == "config" {
		return "", "", false
	}

	needAuth = true
	switch {
	case len(parts) >= 1 && parts[0] == "cluster":
		return "cluster", "read", needAuth
	case len(parts) >= 1 && parts[0] == "pod":
		return "cluster", "read", needAuth
	case len(parts) >= 1 && parts[0] == "services":
		return "services", "read", needAuth
	case len(parts) >= 1 && parts[0] == "metrics":
		return "metrics", "read", needAuth
	case len(parts) >= 1 && parts[0] == "waypoint":
		if len(parts) >= 2 {
			switch parts[1] {
			case "apply":
				return "waypoint", "write", needAuth
			case "delete":
				return "waypoint", "delete", needAuth
			}
		}
		return "waypoint", "read", needAuth
	case len(parts) >= 1 && parts[0] == "circuitbreaker":
		if len(parts) >= 2 {
			switch parts[1] {
			case "apply":
				return "circuitbreaker", "write", needAuth
			case "delete":
				return "circuitbreaker", "delete", needAuth
			}
		}
		return "circuitbreaker", "read", needAuth
	case len(parts) >= 1 && parts[0] == "ratelimit":
		if len(parts) >= 2 {
			switch parts[1] {
			case "apply":
				return "ratelimit", "write", needAuth
			case "delete":
				return "ratelimit", "delete", needAuth
			}
		}
		return "ratelimit", "read", needAuth
	case len(parts) >= 1 && parts[0] == "authorization":
		if len(parts) >= 2 {
			switch parts[1] {
			case "apply":
				return "authorization", "write", needAuth
			case "delete":
				return "authorization", "delete", needAuth
			}
		}
		return "authorization", "read", needAuth
	case len(parts) >= 1 && parts[0] == "auth":
		return "auth", "read", needAuth
	case len(parts) >= 1 && parts[0] == "custom":
		if len(parts) >= 2 && parts[1] == "apply" {
			return "custom", "write", needAuth
		}
		return "custom", "read", needAuth
	default:
		return "cluster", "read", needAuth
	}
}

// AuthMiddleware 校验 JWT 并将 user/role 写入 context；若需认证且无有效 token 返回 401
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		resource, action, needAuth := routePermission(path, r.Method)
		if !needAuth {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization", http.StatusUnauthorized)
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "invalid Authorization", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, prefix)
		username, role, err := ParseToken(token, GetJWTSecret())
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		ctx := WithContext(r.Context(), username, role)
		allowed, err := Enforce(role, resource, action)
		if err != nil || !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// 写/删操作记审计
		if action == "write" || action == "delete" {
			Audit(username, role, resource, action, r.URL.RawQuery)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
