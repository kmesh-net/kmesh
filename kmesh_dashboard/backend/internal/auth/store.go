package auth

import (
	"os"
	"strings"
	"sync"
)

// User 静态用户信息（密码为明文比对，生产建议改为 bcrypt）
type User struct {
	Username string
	Password string
	Role     string
}

var (
	userStore = make(map[string]*User)
	storeMu   sync.RWMutex
)

// InitStaticUsers 从环境变量 DASHBOARD_USERS 加载用户，格式：user1:pass1:role1,user2:pass2:role2
// 若未设置则默认 admin:admin:admin, readonly:readonly:reader
func InitStaticUsers() {
	storeMu.Lock()
	defer storeMu.Unlock()
	userStore = make(map[string]*User)
	raw := os.Getenv("DASHBOARD_USERS")
	if raw == "" {
		raw = "admin:admin:admin,readonly:readonly:reader,editor:editor:editor"
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		seg := strings.SplitN(part, ":", 3)
		if len(seg) != 3 {
			continue
		}
		userStore[seg[0]] = &User{Username: seg[0], Password: seg[1], Role: seg[2]}
	}
}

// VerifyUser 校验用户名密码，返回角色；失败返回空角色
func VerifyUser(username, password string) (role string, ok bool) {
	storeMu.RLock()
	defer storeMu.RUnlock()
	u, exists := userStore[username]
	if !exists || u.Password != password {
		return "", false
	}
	return u.Role, true
}

// GetUserRole 仅查角色（不校验密码）
func GetUserRole(username string) (role string, ok bool) {
	storeMu.RLock()
	defer storeMu.RUnlock()
	u, exists := userStore[username]
	if !exists {
		return "", false
	}
	return u.Role, true
}
