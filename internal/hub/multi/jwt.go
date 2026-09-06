package multi

import (
	"context"
	"database/sql"
	"fmt"
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
// fail-closed：无 Token / 解析失败一律 401，租户隔离不能被静默绕过。
func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") || authHeader == "Bearer " {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &tenantClaims{}, func(t *jwt.Token) (interface{}, error) {
			// 算法白名单：拒绝 alg=none / 算法混淆攻击
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return m.jwtSecret, nil
		})
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*tenantClaims)
		if !ok || !token.Valid || claims.TenantID == "" {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// 设置 PostgreSQL session 变量：SET 不支持绑定参数，
		// 必须用 set_config()，否则 RLS 策略（current_setting('app.tenant_id')）永远取不到值
		if m.db != nil {
			if _, err := m.db.ExecContext(r.Context(),
				"SELECT set_config('app.tenant_id', $1, false)", claims.TenantID); err != nil {
				// 租户会话变量设置失败意味着 RLS 不生效，必须拒绝请求而不是放行
				http.Error(w, `{"error":"tenant session setup failed"}`, http.StatusInternalServerError)
				return
			}
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
