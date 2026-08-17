package rbac

import (
	"fmt"
	"strings"
)

// Role 角色
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	RoleAuditor  Role = "auditor"
)

// Permission 权限
type Permission string

const (
	PermServerManage  Permission = "server:manage"
	PermServerView    Permission = "server:view"
	PermAlertManage   Permission = "alert:manage"
	PermAlertView     Permission = "alert:view"
	PermRuleManage    Permission = "rule:manage"
	PermRuleView      Permission = "rule:view"
	PermCertManage    Permission = "cert:manage"
	PermCertView      Permission = "cert:view"
	PermFindingManage Permission = "finding:manage"
	PermFindingView   Permission = "finding:view"
	PermAuditView     Permission = "audit:view"
	PermConfigManage  Permission = "config:manage"
	PermUserManage    Permission = "user:manage"
	PermBillingManage Permission = "billing:manage"
	PermEmergencyStop Permission = "emergency:stop"
)

// rolePermissions 角色权限矩阵
var rolePermissions = map[Role][]Permission{
	RoleOwner: {
		PermServerManage, PermServerView,
		PermAlertManage, PermAlertView,
		PermRuleManage, PermRuleView,
		PermCertManage, PermCertView,
		PermFindingManage, PermFindingView,
		PermAuditView,
		PermConfigManage, PermUserManage, PermBillingManage,
		PermEmergencyStop,
	},
	RoleAdmin: {
		PermServerManage, PermServerView,
		PermAlertManage, PermAlertView,
		PermRuleManage, PermRuleView,
		PermCertManage, PermCertView,
		PermFindingManage, PermFindingView,
		PermAuditView,
		PermConfigManage, PermEmergencyStop,
	},
	RoleOperator: {
		PermServerManage, PermServerView,
		PermAlertManage, PermAlertView,
		PermRuleView,
		PermCertView,
		PermFindingManage, PermFindingView,
		PermEmergencyStop,
	},
	RoleViewer: {
		PermServerView,
		PermAlertView,
		PermRuleView,
		PermCertView,
		PermFindingView,
	},
	RoleAuditor: {
		PermAuditView,
	},
}

// HasPermission 检查角色是否有指定权限
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// GetRolePermissions 获取角色的所有权限
func GetRolePermissions(role Role) []Permission {
	return rolePermissions[role]
}

// ValidRoles 有效角色列表
func ValidRoles() []Role {
	return []Role{RoleOwner, RoleAdmin, RoleOperator, RoleViewer, RoleAuditor}
}

// IsValidRole 检查角色是否有效
func IsValidRole(role Role) bool {
	_, ok := rolePermissions[role]
	return ok
}

// RoleDescription 角色描述
func RoleDescription(role Role) string {
	switch role {
	case RoleOwner:
		return "所有者：全部权限"
	case RoleAdmin:
		return "管理员：不可管理计费和 Owner 用户"
	case RoleOperator:
		return "操作员：不可改全局规则和用户权限"
	case RoleViewer:
		return "查看者：只读权限"
	case RoleAuditor:
		return "审计员：仅审计日志"
	default:
		return fmt.Sprintf("未知角色: %s", role)
	}
}

// ParseRole 从字符串解析角色
func ParseRole(s string) (Role, error) {
	role := Role(strings.ToLower(s))
	if !IsValidRole(role) {
		return "", fmt.Errorf("invalid role: %s", s)
	}
	return role, nil
}
