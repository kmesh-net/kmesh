package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// KialiURL 从 KIALI_URL 环境变量读取浏览器可访问的 Kiali 地址，供拓扑页跳转用
// 支持完整 URL（如 http://47.121.202.218:20001/kiali）或仅 host:port（自动补 /kiali）
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

// Config 返回 Kiali 地址，供拓扑页跳转
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
