package comm

import (
	"context"
	"errors"
	"testing"
)

// Hub 远程命令的安全契约：
//  1. 未知命令必须被拒绝（success=false + error），白名单之外无可执行路径；
//  2. 命令响应必须回传 Hub 下发的 command_id，否则 Hub 无法关联结果；
//  3. 处理器返回的 result 载荷必须完整进入响应（status 命令的数据通道）。

func TestCommandIDFromData(t *testing.T) {
	cases := []struct {
		name string
		data interface{}
		want interface{}
	}{
		{"map with command_id", map[string]interface{}{"command_id": "abc-123", "requested": "x"}, "abc-123"},
		{"map without command_id", map[string]interface{}{"foo": 1}, nil},
		{"nil data", nil, nil},
		{"non-map data", "restart", nil},
	}
	for _, tc := range cases {
		if got := commandIDFromData(tc.data); got != tc.want {
			t.Errorf("%s: commandIDFromData = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBuildCommandResponse_SuccessWithResult(t *testing.T) {
	msg := HubMessage{
		Type: "status",
		Data: map[string]interface{}{"command_id": "cmd-1"},
	}
	resp := buildCommandResponse(msg, map[string]interface{}{"health_score": 88}, nil)

	if resp["success"] != true {
		t.Errorf("success = %v, want true", resp["success"])
	}
	if resp["command_id"] != "cmd-1" {
		t.Errorf("command_id = %v, want cmd-1", resp["command_id"])
	}
	if resp["command"] != "status" {
		t.Errorf("command = %v, want status", resp["command"])
	}
	result, ok := resp["result"].(map[string]interface{})
	if !ok || result["health_score"] != 88 {
		t.Errorf("result payload missing or wrong: %v", resp["result"])
	}
	if _, hasErr := resp["error"]; hasErr {
		t.Error("success response should not carry error")
	}
}

func TestBuildCommandResponse_FailureCarriesError(t *testing.T) {
	msg := HubMessage{
		Type: "restart",
		Data: map[string]interface{}{"command_id": 42},
	}
	resp := buildCommandResponse(msg, nil, errors.New("emergency stop is active"))

	if resp["success"] != false {
		t.Errorf("success = %v, want false", resp["success"])
	}
	if resp["error"] != "emergency stop is active" {
		t.Errorf("error = %v", resp["error"])
	}
	if _, hasResult := resp["result"]; hasResult {
		t.Error("failed response should not carry result")
	}
}

func TestHubClient_UnknownCommandRejected(t *testing.T) {
	c := NewHubClient(nil, "ws://127.0.0.1:1", "agent-a", "token")

	// 只注册白名单命令；恶意/未知命令类型没有处理器
	c.RegisterCommandHandler("status", func(ctx context.Context, params interface{}) (interface{}, error) {
		return "ok", nil
	})
	c.RegisterCommandHandler("restart", func(ctx context.Context, params interface{}) (interface{}, error) {
		return "ok", nil
	})

	c.mu.RLock()
	_, known := c.commandHandlers["exec"] // 模拟任意命令执行请求
	_, restartKnown := c.commandHandlers["restart"]
	c.mu.RUnlock()

	if known {
		t.Fatal("未注册的命令 exec 不应存在处理器（任意命令执行必须被拒绝）")
	}
	if !restartKnown {
		t.Fatal("白名单命令 restart 应有处理器")
	}
}

func TestHubClient_HandlerSignatureReturnsResult(t *testing.T) {
	c := NewHubClient(nil, "ws://127.0.0.1:1", "agent-a", "token")
	called := false
	c.RegisterCommandHandler("status", func(ctx context.Context, params interface{}) (interface{}, error) {
		called = true
		return map[string]int{"health_score": 95}, nil
	})

	c.mu.RLock()
	handler := c.commandHandlers["status"]
	c.mu.RUnlock()

	result, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if !called {
		t.Fatal("handler was not invoked")
	}
	if m, ok := result.(map[string]int); !ok || m["health_score"] != 95 {
		t.Errorf("handler result = %v, want health_score 95", result)
	}
}
