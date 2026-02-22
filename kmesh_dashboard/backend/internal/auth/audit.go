package auth

import (
	"log"
	"os"
	"sync"
	"time"
)

var (
	auditMu sync.Mutex
)

// Audit 记录关键操作审计日志（用户、资源、操作、详情）；可扩展为写文件或集群 Event
func Audit(username, role, resource, action, detail string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	ts := time.Now().Format(time.RFC3339)
	line := ts + " user=" + username + " role=" + role + " resource=" + resource + " action=" + action
	if detail != "" {
		line += " detail=" + detail
	}
	log.New(os.Stdout, "[AUDIT] ", 0).Println(line)
}
