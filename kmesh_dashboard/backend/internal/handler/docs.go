package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// docsDir 返回文档目录绝对路径
func docsDir() string {
	if d := os.Getenv("DOCS_DIR"); d != "" {
		return d
	}
	wd, _ := os.Getwd()
	// 兼容：从 kmesh_dashboard 或 backend 目录启动
	for _, p := range []string{
		filepath.Join(wd, "docs"),
		filepath.Join(wd, "..", "docs"),
	} {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	return filepath.Join(wd, "..", "docs")
}

// Docs 统一处理 /api/docs（列表）和 /api/docs/xxx（内容）
func Docs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		prefix := apiPrefix + "/docs"
		path := r.URL.Path
		// /api/docs 或 /api/docs/ -> 返回列表（与顶部导航顺序一致：集群节点、服务拓扑、Waypoint、熔断、认证策略、限流、指标）
		if path == prefix || path == prefix+"/" {
			dir := docsDir()
			if _, err := os.Stat(dir); err != nil {
				http.Error(w, "docs directory not found", http.StatusNotFound)
				return
			}
			docOrder := []string{"cluster", "topology", "waypoint", "circuitbreaker", "authorization", "ratelimit", "metrics"}
			var result []string
			for _, name := range docOrder {
				docPath := filepath.Join(dir, name+".md")
				if _, err := os.Stat(docPath); err == nil {
					result = append(result, name)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"docs": result})
			return
		}
		// /api/docs/xxx -> 返回文档内容，支持 ?lang=en 获取英文版
		if strings.HasPrefix(path, prefix+"/") {
			name := strings.TrimPrefix(path, prefix+"/")
			if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
				http.Error(w, "invalid doc name", http.StatusBadRequest)
				return
			}
			baseDir := docsDir()
			docPath := filepath.Join(baseDir, name+".md")
			// 英文版：优先 X-Doc-Lang: en（前端显式传），其次 ?lang=en，最后 Accept-Language
			useEn := r.Header.Get("X-Doc-Lang") == "en" || r.URL.Query().Get("lang") == "en"
			if !useEn && r.Header.Get("Accept-Language") != "" {
				for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
					if strings.HasPrefix(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "en") {
						useEn = true
						break
					}
				}
			}
			if useEn {
				enPath := filepath.Join(baseDir, "en", name+".md")
				if _, err := os.Stat(enPath); err == nil {
					docPath = enPath
				}
			}
			data, err := os.ReadFile(docPath)
			if err != nil {
				http.Error(w, "doc not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		http.NotFound(w, r)
	}
}
