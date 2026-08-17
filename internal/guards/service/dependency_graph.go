package service

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type DependencyGraph struct {
	mu   sync.RWMutex
	edges map[string][]string
}

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		edges: make(map[string][]string),
	}
}

func (g *DependencyGraph) AddDependency(service, dependsOn string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[service] = append(g.edges[service], dependsOn)
}

func (g *DependencyGraph) RemoveDependency(service, dependsOn string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	deps := g.edges[service]
	for i, d := range deps {
		if d == dependsOn {
			g.edges[service] = append(deps[:i], deps[i+1:]...)
			return
		}
	}
}

func (g *DependencyGraph) GetDependencies(service string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.edges[service]
}

func (g *DependencyGraph) IsCyclic() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]int)
	for node := range g.edges {
		if visited[node] == 0 {
			if g.dfsCycle(node, visited) {
				return true
			}
		}
	}
	return false
}

func (g *DependencyGraph) dfsCycle(node string, visited map[string]int) bool {
	visited[node] = 1
	for _, dep := range g.edges[node] {
		if visited[dep] == 1 {
			return true
		}
		if visited[dep] == 0 {
			if g.dfsCycle(dep, visited) {
				return true
			}
		}
	}
	visited[node] = 2
	return false
}

func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	if g.IsCyclic() {
		return nil, fmt.Errorf("circular dependency detected, cannot sort")
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	inDegree := make(map[string]int)
	allNodes := make(map[string]bool)

	for svc, deps := range g.edges {
		allNodes[svc] = true
		for _, dep := range deps {
			allNodes[dep] = true
			inDegree[svc]++
		}
	}

	var queue []string
	for node := range allNodes {
		if inDegree[node] == 0 {
			queue = append(queue, node)
		}
	}
	sort.Strings(queue)

	var result []string
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		for svc, deps := range g.edges {
			for _, dep := range deps {
				if dep == node {
					inDegree[svc]--
					if inDegree[svc] == 0 {
						queue = append(queue, svc)
						sort.Strings(queue)
					}
				}
			}
		}
	}

	return result, nil
}

func (g *DependencyGraph) GetAffectedServices(downService string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	affected := make(map[string]bool)
	queue := []string{downService}

	for len(queue) > 0 {
		svc := queue[0]
		queue = queue[1:]

		for service, deps := range g.edges {
			for _, dep := range deps {
				if dep == svc && !affected[service] {
					affected[service] = true
					queue = append(queue, service)
				}
			}
		}
	}

	var result []string
	for s := range affected {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

func (g *DependencyGraph) Visualize() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	for svc, deps := range g.edges {
		if len(deps) == 0 {
			sb.WriteString(fmt.Sprintf("%s\n", svc))
		} else {
			sb.WriteString(fmt.Sprintf("%s -> %s\n", svc, strings.Join(deps, ", ")))
		}
	}
	return sb.String()
}

type PortConflictResolver struct {
	mu       sync.RWMutex
	history  map[int][]PortUsageRecord
}

type PortUsageRecord struct {
	Port      int
	PID       int32
	Process   string
	Timestamp time.Time
	IsZombie  bool
}

func NewPortConflictResolver() *PortConflictResolver {
	return &PortConflictResolver{
		history: make(map[int][]PortUsageRecord),
	}
}

func (r *PortConflictResolver) CheckPortConflict(port int) (*PortUsageRecord, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		return nil, nil
	}

	record := PortUsageRecord{
		Port:      port,
		Timestamp: time.Now(),
	}
	r.mu.Lock()
	r.history[port] = append(r.history[port], record)
	r.mu.Unlock()

	return &record, nil
}

func (r *PortConflictResolver) GetPortHistory(port int) []PortUsageRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.history[port]
}

func (r *PortConflictResolver) GetPortMap() map[int][]PortUsageRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[int][]PortUsageRecord)
	for k, v := range r.history {
		result[k] = v
	}
	return result
}

type ExponentialBackoff struct {
	initial    time.Duration
	maximum    time.Duration
	multiplier float64
	maxRetries int
	current    time.Duration
	attempts   int
}

func NewExponentialBackoff() *ExponentialBackoff {
	return &ExponentialBackoff{
		initial:    1 * time.Second,
		maximum:    16 * time.Second,
		multiplier: 2.0,
		maxRetries: 5,
		current:    1 * time.Second,
	}
}

func (e *ExponentialBackoff) Next() time.Duration {
	if e.attempts >= e.maxRetries {
		return 0
	}
	d := e.current
	e.current = time.Duration(float64(e.current) * e.multiplier)
	if e.current > e.maximum {
		e.current = e.maximum
	}
	e.attempts++
	return d
}

func (e *ExponentialBackoff) IsExhausted() bool {
	return e.attempts >= e.maxRetries
}

func (e *ExponentialBackoff) Reset() {
	e.attempts = 0
	e.current = e.initial
}