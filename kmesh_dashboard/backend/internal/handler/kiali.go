package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// KialiURL reads a browser-accessible Kiali address from KIALI_URL for topology page redirection.
// It supports a full URL (e.g. http://kiali.kmesh-system:20001) or host:port (auto-appends /kiali).
func KialiURL() string {
	u := os.Getenv("KIALI_URL")
	if u == "" {
		return ""
	}
	u = strings.TrimSpace(strings.TrimSuffix(u, "/"))
	if u == "" {
		return ""
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	if !strings.Contains(u, "/kiali") {
		u = strings.TrimSuffix(u, "/") + "/kiali"
	}
	return u + "/"
}

// Config returns the Kiali URL for topology page redirection.
func Config() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"kialiUrl": KialiURL(),
		})
	}
}
