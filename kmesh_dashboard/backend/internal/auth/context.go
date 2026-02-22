package auth

import (
	"context"
)

type contextKey string

const contextKeyUser contextKey = "auth_user"
const contextKeyRole contextKey = "auth_role"

// WithContext 将 username、role 写入 context
func WithContext(ctx context.Context, username, role string) context.Context {
	ctx = context.WithValue(ctx, contextKeyUser, username)
	ctx = context.WithValue(ctx, contextKeyRole, role)
	return ctx
}

// FromContext 从 context 读取 username、role
func FromContext(ctx context.Context) (username, role string) {
	u, _ := ctx.Value(contextKeyUser).(string)
	r, _ := ctx.Value(contextKeyRole).(string)
	return u, r
}
