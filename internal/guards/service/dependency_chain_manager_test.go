package service

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestDependencyChainManager_IsolateDownstream(t *testing.T) {
	graph := NewDependencyGraph()
	// API -> MySQL, Web -> API
	graph.AddDependency("api", "mysql")
	graph.AddDependency("web", "api")

	mgr := NewDependencyChainManager(graph)

	// MySQL 宕机，隔离下游
	isolated := mgr.IsolateDownstream("mysql")
	if len(isolated) == 0 {
		t.Error("should isolate downstream services")
	}
	if !mgr.IsIsolated("api") {
		t.Error("api should be isolated")
	}
}

func TestDependencyChainManager_RestoreInOrder(t *testing.T) {
	graph := NewDependencyGraph()
	graph.AddDependency("api", "mysql")
	graph.AddDependency("web", "api")

	mgr := NewDependencyChainManager(graph)
	mgr.IsolateDownstream("mysql")

	startFunc := func(svc string) error {
		return nil
	}
	healthCheckFunc := func(ctx context.Context, svc string) bool {
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	succeeded, failed := mgr.RestoreInOrder(ctx, "mysql", startFunc, healthCheckFunc)

	if len(failed) > 0 {
		t.Errorf("should have no failures, got %d", len(failed))
	}
	if len(succeeded) == 0 {
		t.Error("should have succeeded services")
	}
}

func TestDependencyChainManager_IsIsolated(t *testing.T) {
	graph := NewDependencyGraph()
	mgr := NewDependencyChainManager(graph)

	if mgr.IsIsolated("nonexistent") {
		t.Error("nonexistent service should not be isolated")
	}
}

func TestEnhancedPortConflictResolver_GetConflictHistory(t *testing.T) {
	r := NewEnhancedPortConflictResolver(nil)
	history := r.GetConflictHistory(8080)
	if len(history) != 0 {
		t.Error("initial history should be empty")
	}
}

func TestPortConflictDetail(t *testing.T) {
	detail := PortConflictDetail{
		Port:    8080,
		PID:     1234,
		Process: "test",
		Status:  "running",
	}
	if detail.Port != 8080 {
		t.Error("port should be 8080")
	}
	_ = fmt.Sprintf("%v", detail)
}
