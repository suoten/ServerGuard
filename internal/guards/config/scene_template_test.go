package config

import (
	"strings"
	"testing"
)

// 场景模板是"更好用"的入口：数据坏了一键应用就写坏规则，必须守约。
func TestBuiltinTemplates_Sane(t *testing.T) {
	templates := BuiltinTemplates()
	if len(templates) < 3 {
		t.Fatalf("至少应内置 3 个场景模板，实际 %d", len(templates))
	}

	seen := make(map[string]bool)
	for _, tmpl := range templates {
		if tmpl.ID == "" || tmpl.Name == "" {
			t.Fatalf("模板 ID/Name 不能为空: %+v", tmpl)
		}
		if seen[tmpl.ID] {
			t.Errorf("模板 ID 重复: %s", tmpl.ID)
		}
		seen[tmpl.ID] = true

		if len(tmpl.Rules) == 0 && len(tmpl.GuardTargets) == 0 {
			t.Errorf("模板 %s 既无规则也无守护目标，应用后是空操作", tmpl.ID)
		}
		for _, rt := range tmpl.Rules {
			if rt.Name == "" {
				t.Errorf("模板 %s 存在无名规则", tmpl.ID)
			}
		}
	}

	// 三个核心场景必须存在（WordPress 站长 / 组合服务 / Java 应用）
	for _, want := range []string{"wordpress", "nginx-mysql-redis", "spring-boot"} {
		if !seen[want] {
			t.Errorf("缺少核心场景模板 %q", want)
		}
	}
}

// FindTemplate：存在返回指针、不存在返回 nil（apply API 依赖此约定）。
func TestFindTemplate(t *testing.T) {
	if FindTemplate("wordpress") == nil {
		t.Fatal("wordpress 模板应存在")
	}
	if FindTemplate("no-such-template") != nil {
		t.Error("不存在的模板应返回 nil")
	}
}

// WordPress 模板内容抽查：应有 PHP/上传相关守护与规则。
func TestWordPressTemplate_Content(t *testing.T) {
	tmpl := FindTemplate("wordpress")
	if tmpl == nil {
		t.Fatal("wordpress 模板应存在")
	}
	joined := strings.ToLower(tmpl.Name + tmpl.Description)
	if !strings.Contains(joined, "wordpress") {
		t.Errorf("WordPress 模板描述应说明适用场景，实际 %q", joined)
	}
}
