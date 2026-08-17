package rbac

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// contextKey 上下文键类型
type contextKey string

const (
	ContextKeyUser   contextKey = "user"
	ContextKeyRole   contextKey = "role"
	ContextKeyTenant contextKey = "tenant_id"
)

// JWTClaims JWT 声明
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Role     Role   `json:"role"`
	TenantID string `json:"tenant_id"`
	jwt.RegisteredClaims
}

// RBACMiddleware RBAC 中间件
type RBACMiddleware struct {
	jwtSecret []byte
}

// NewRBACMiddleware 创建 RBAC 中间件
func NewRBACMiddleware(jwtSecret string) *RBACMiddleware {
	return &RBACMiddleware{jwtSecret: []byte(jwtSecret)}
}

// ParseJWT 解析 JWT token
func (m *RBACMiddleware) ParseJWT(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrTokenInvalidClaims
}

// Middleware HTTP 中间件，解析 JWT 并注入上下文
func (m *RBACMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := m.ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ContextKeyUser, claims.UserID)
		ctx = context.WithValue(ctx, ContextKeyRole, claims.Role)
		ctx = context.WithValue(ctx, ContextKeyTenant, claims.TenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission 权限检查中间件
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(ContextKeyRole).(Role)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !HasPermission(role, perm) {
				http.Error(w, "forbidden: insufficient permissions", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserID 从上下文获取用户 ID
func GetUserID(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyUser).(string); ok {
		return v
	}
	return ""
}

// GetRole 从上下文获取角色
func GetRole(ctx context.Context) Role {
	if v, ok := ctx.Value(ContextKeyRole).(Role); ok {
		return v
	}
	return RoleViewer
}

// GetTenantID 从上下文获取租户 ID
func GetTenantID(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyTenant).(string); ok {
		return v
	}
	return ""
}

// GenerateToken 生成 JWT token
func (m *RBACMiddleware) GenerateToken(userID string, role Role, tenantID string) (string, error) {
	claims := &JWTClaims{
		UserID:   userID,
		Role:     role,
		TenantID: tenantID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}
