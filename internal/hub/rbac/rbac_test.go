package rbac

import (
	"testing"
)

func TestHasPermission(t *testing.T) {
	// Owner 应有所有权限
	if !HasPermission(RoleOwner, PermServerManage) {
		t.Error("Owner should have PermServerManage")
	}
	if !HasPermission(RoleOwner, PermBillingManage) {
		t.Error("Owner should have PermBillingManage")
	}

	// Admin 不应有计费权限
	if HasPermission(RoleAdmin, PermBillingManage) {
		t.Error("Admin should not have PermBillingManage")
	}

	// Operator 不应有用户管理权限
	if HasPermission(RoleOperator, PermUserManage) {
		t.Error("Operator should not have PermUserManage")
	}

	// Viewer 不应有任何修改权限
	if HasPermission(RoleViewer, PermServerManage) {
		t.Error("Viewer should not have PermServerManage")
	}
	if !HasPermission(RoleViewer, PermServerView) {
		t.Error("Viewer should have PermServerView")
	}

	// Auditor 仅审计权限
	if !HasPermission(RoleAuditor, PermAuditView) {
		t.Error("Auditor should have PermAuditView")
	}
	if HasPermission(RoleAuditor, PermServerView) {
		t.Error("Auditor should not have PermServerView")
	}
}

func TestIsValidRole(t *testing.T) {
	validRoles := []Role{RoleOwner, RoleAdmin, RoleOperator, RoleViewer, RoleAuditor}
	for _, role := range validRoles {
		if !IsValidRole(role) {
			t.Errorf("%s should be valid", role)
		}
	}

	if IsValidRole("superadmin") {
		t.Error("superadmin should not be valid")
	}
}

func TestParseRole(t *testing.T) {
	role, err := ParseRole("ADMIN")
	if err != nil {
		t.Fatalf("ParseRole failed: %v", err)
	}
	if role != RoleAdmin {
		t.Errorf("expected RoleAdmin, got %s", role)
	}

	_, err = ParseRole("invalid")
	if err == nil {
		t.Error("ParseRole should fail for invalid role")
	}
}

func TestRoleDescription(t *testing.T) {
	desc := RoleDescription(RoleOwner)
	if desc == "" {
		t.Error("RoleDescription should not be empty")
	}

	desc = RoleDescription(RoleAuditor)
	if desc == "" {
		t.Error("RoleDescription should not be empty")
	}
}

func TestGetRolePermissions(t *testing.T) {
	perms := GetRolePermissions(RoleOwner)
	if len(perms) == 0 {
		t.Error("Owner should have permissions")
	}

	perms = GetRolePermissions(RoleViewer)
	if len(perms) == 0 {
		t.Error("Viewer should have permissions")
	}
}
