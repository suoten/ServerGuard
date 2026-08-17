package service

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DependencyChainManager 依赖链管理器。
// 上游宕机时隔离下游避免误判，上游恢复后按拓扑序逐个拉起。
type DependencyChainManager struct {
	mu       sync.Mutex
	graph    *DependencyGraph
	isolated map[string]bool // 被隔离的服务集合
}

// NewDependencyChainManager 创建依赖链管理器。
func NewDependencyChainManager(graph *DependencyGraph) *DependencyChainManager {
	return &DependencyChainManager{
		graph:    graph,
		isolated: make(map[string]bool),
	}
}

// IsolateDownstream 上游宕机时标记下游节点为 isolated 状态，暂停下游监控避免误判。
// 返回被隔离的服务列表。
func (m *DependencyChainManager) IsolateDownstream(nodeID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 获取所有下游服务（直接和间接依赖 nodeID 的服务）
	downstream := m.graph.GetAffectedServices(nodeID)
	for _, svc := range downstream {
		m.isolated[svc] = true
	}

	return downstream
}

// RestoreInOrder 上游恢复后按拓扑序逐个拉起下游。
// 每个节点启动后阻塞等 HealthCheck 通过再拉起下一个。
// startFunc: 启动服务的函数
// healthCheckFunc: 健康检查函数，返回 true 表示通过
// 返回拉起成功和失败的服务列表。
func (m *DependencyChainManager) RestoreInOrder(
	ctx context.Context,
	nodeID string,
	startFunc func(service string) error,
	healthCheckFunc func(ctx context.Context, service string) bool,
) (succeeded []string, failed []string) {
	m.mu.Lock()
	downstream := m.graph.GetAffectedServices(nodeID)
	// 按拓扑序排序
	ordered := m.topologicalSort(downstream)
	m.mu.Unlock()

	for _, svc := range ordered {
		select {
		case <-ctx.Done():
			return succeeded, failed
		default:
		}

		// 启动服务
		if err := startFunc(svc); err != nil {
			failed = append(failed, svc)
			continue
		}

		// 等待健康检查通过（最多 30s）
		checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		passed := waitForHealthCheck(checkCtx, svc, healthCheckFunc)
		cancel()

		if passed {
			succeeded = append(succeeded, svc)
			m.mu.Lock()
			delete(m.isolated, svc)
			m.mu.Unlock()
		} else {
			failed = append(failed, svc)
		}
	}

	return succeeded, failed
}

// IsIsolated 检查服务是否被隔离。
func (m *DependencyChainManager) IsIsolated(service string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isolated[service]
}

// GetIsolatedServices 返回所有被隔离的服务。
func (m *DependencyChainManager) GetIsolatedServices() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []string
	for svc := range m.isolated {
		result = append(result, svc)
	}
	return result
}

// topologicalSort 对服务列表进行拓扑排序。
func (m *DependencyChainManager) topologicalSort(services []string) []string {
	// 简单实现：按依赖深度排序
	// 被依赖少的服务先启动
	depth := make(map[string]int)
	for _, svc := range services {
		depth[svc] = m.getDepth(svc)
	}

	// 按深度从小到大排序
	result := make([]string, len(services))
	copy(result, services)

	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if depth[result[j]] < depth[result[i]] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// getDepth 获取服务在依赖图中的深度。
func (m *DependencyChainManager) getDepth(service string) int {
	deps := m.graph.GetDependencies(service)
	if len(deps) == 0 {
		return 0
	}
	maxDepDepth := 0
	for _, dep := range deps {
		d := m.getDepth(dep)
		if d > maxDepDepth {
			maxDepDepth = d
		}
	}
	return maxDepDepth + 1
}

// waitForHealthCheck 等待健康检查通过，每 2s 检查一次。
func waitForHealthCheck(ctx context.Context, service string, checkFunc func(ctx context.Context, service string) bool) bool {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if checkFunc(ctx, service) {
				return true
			}
		}
	}
}

// String 返回隔离状态的字符串表示。
func (m *DependencyChainManager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("DependencyChainManager{isolated: %d services}", len(m.isolated))
}