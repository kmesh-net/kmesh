package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultJWTSecret = "kmesh-dashboard-secret-change-in-production"
const defaultExpire = 24 * time.Hour

var (
	ErrInvalidToken = errors.New("invalid token")
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// CreateToken 签发 JWT，sub=username，自定义 claim 存 role
func CreateToken(username, role string, secret string, expire time.Duration) (string, error) {
	if secret == "" {
		secret = defaultJWTSecret
	}
	if expire <= 0 {
		expire = defaultExpire
	}
	claims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expire)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ParseToken 解析并校验 JWT，返回 username、role
func ParseToken(tokenString string, secret string) (username, role string, err error) {
	if secret == "" {
		secret = defaultJWTSecret
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return "", "", ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", "", ErrInvalidToken
	}
	return claims.Username, claims.Role, nil
}
