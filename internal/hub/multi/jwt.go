package multi

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWTMiddleware 多租户 JWT 中间件
// 解析 JWT 提取 tenant_id 和 role，设置 PostgreSQL session SET app.tenant_id
type JWTMiddleware struct {
	jwtSecret []byte
	db        *sql.DB
}

// NewJWTMiddleware 创建 JWT 中间件
func NewJWTMiddleware(jwtSecret string, db *sql.DB) *JWTMiddleware {
	return &JWTMiddleware{
		jwtSecret: []byte(jwtSecret),
		db:        db,
	}
}

// tenantClaims JWT 声明
type tenantClaims struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	UserID   string `json:"user_id"`
	jwt.RegisteredClaims
}

// Middleware HTTP 中间件
func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &tenantClaims{}, func(t *jwt.Token) (interface{}, error) {
			return m.jwtSecret, nil
		})
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		claims, ok := token.Claims.(*tenantClaims)
		if !ok || !token.Valid {
			next.ServeHTTP(w, r)
			return
		}

		// 设置 PostgreSQL session 变量
		if m.db != nil && claims.TenantID != "" {
			_, _ = m.db.ExecContext(r.Context(), "SET app.tenant_id = $1", claims.TenantID)
		}

		// 注入上下文
		ctx := context.WithValue(r.Context(), "tenant_id", claims.TenantID)
		ctx = context.WithValue(ctx, "user_role", claims.Role)
		ctx = context.WithValue(ctx, "user_id", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetTenantIDFromContext 从上下文获取租户 ID
func GetTenantIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value("tenant_id").(string); ok {
		return v
	}
	return ""
}

// GetRoleFromContext 从上下文获取角色
func GetRoleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value("user_role").(string); ok {
		return v
	}
	return ""
}
