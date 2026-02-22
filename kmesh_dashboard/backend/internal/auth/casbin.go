package auth

import (
	"path/filepath"
	"sync"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

var (
	enforcer *casbin.Enforcer
	enforcerOnce sync.Once
)

// InitEnforcer 从 model.conf 与 policy.csv 初始化 Casbin Enforcer（默认与可执行文件同目录的 internal/auth）
func InitEnforcer(modelPath, policyPath string) (*casbin.Enforcer, error) {
	var err error
	enforcerOnce.Do(func() {
		if modelPath == "" {
			modelPath = "internal/auth/model.conf"
		}
		if policyPath == "" {
			policyPath = "internal/auth/policy.csv"
		}
		modelPath = filepath.Clean(modelPath)
		policyPath = filepath.Clean(policyPath)
		a := fileadapter.NewAdapter(policyPath)
		enforcer, err = casbin.NewEnforcer(modelPath, a)
	})
	return enforcer, err
}

// Enforce 校验角色 role 对 resource 是否有 action 权限（role 来自 JWT）
func Enforce(role, resource, action string) (bool, error) {
	if enforcer == nil {
		return false, nil
	}
	return enforcer.Enforce(role, resource, action)
}

// GetEnforcer 返回全局 Enforcer（需已 InitEnforcer）
func GetEnforcer() *casbin.Enforcer {
	return enforcer
}
