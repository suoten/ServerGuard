package docker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/agent/safety"
	"github.com/suoten/serverguard/internal/types"
)

// DockerGuard implements Module G: Docker Guard
// Covers: container health monitoring, OOM detection, resource limit suggestions,
// image cleanup suggestions, log limit recommendations.
//
// SAFETY: Never auto-restarts containers, never auto-prunes volumes/networks.
// All remediation is provided as suggestions for manual execution.
// Auto-restarting containers can cause data corruption (e.g., during DB persistence).
type DockerGuard struct {
	mu          sync.RWMutex
	eventBus    *eventbus.EventBus
	safety      *safety.SafetyManager
	socket      string
	monitored   []string
	oomHistory  map[string]int // container name -> OOM kill count
}

// New creates a new DockerGuard.
func New(bus *eventbus.EventBus, socket string) *DockerGuard {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	return &DockerGuard{
		eventBus:   bus,
		socket:     socket,
		monitored:  []string{},
		oomHistory: make(map[string]int),
	}
}

// SetSafetyManager 注入安全管理器。
func (g *DockerGuard) SetSafetyManager(sm *safety.SafetyManager) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.safety = sm
}

// Check checks container status and provides detailed diagnostics.
func (g *DockerGuard) Check(ctx context.Context) {
	g.checkContainers(ctx)
	g.checkOOMKills(ctx)
	g.checkResourceUsage(ctx)
	g.checkDanglingImages(ctx)
}

// checkContainers checks if monitored containers are running and healthy.
func (g *DockerGuard) checkContainers(ctx context.Context) {
	g.mu.RLock()
	monitored := g.monitored
	g.mu.RUnlock()

	if len(monitored) == 0 {
		// Auto-discover running containers
		g.autoDiscoverContainers(ctx)
		return
	}

	output, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--format",
		"{{.Names}}\t{{.Status}}\t{{.Image}}").Output()
	if err != nil {
		return
	}

	containerStatus := make(map[string][]string)
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			containerStatus[parts[0]] = parts[1:]
		}
	}

	for _, name := range monitored {
		status, exists := containerStatus[name]
		if !exists {
			g.eventBus.PublishAlert(types.AlertError, "docker",
				fmt.Sprintf("容器不存在: %s", name),
				fmt.Sprintf("Docker容器 %s 不存在。\n可能已被删除。请检查:\n  docker ps -a | grep %s", name, name),
				"container-missing-001")
			continue
		}

		statusStr := status[0]
		statusLower := strings.ToLower(statusStr)

		if strings.Contains(statusLower, "exited") || strings.Contains(statusLower, "dead") {
			// Get exit code and logs
			g.reportContainerExited(ctx, name, statusStr)
		} else if strings.Contains(statusLower, "unhealthy") {
			g.reportContainerUnhealthy(ctx, name, statusStr)
		} else if strings.Contains(statusLower, "restarting") {
			g.eventBus.PublishAlert(types.AlertCritical, "docker",
				fmt.Sprintf("容器反复重启: %s", name),
				fmt.Sprintf("Docker容器 %s 正在反复重启 (%s)\n\n"+
					"排查:\n"+
					"  1. 查看日志: docker logs --tail 100 %s\n"+
					"  2. 检查配置: docker inspect %s\n"+
					"  3. 检查端口冲突: docker port %s\n"+
					"  4. 检查资源限制: docker stats %s\n\n"+
					"如需手动重启: docker restart %s",
					name, statusStr, name, name, name, name, name),
				"container-restart-001")
		}
	}
}

// reportContainerExited reports detailed info about an exited container.
func (g *DockerGuard) reportContainerExited(ctx context.Context, name, status string) {
	// Get exit code
	inspectOutput, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.ExitCode}} {{.State.Error}} {{.State.OOMKilled}}", name).Output()
	exitInfo := ""
	if err == nil {
		exitInfo = strings.TrimSpace(string(inspectOutput))
	}

	// Get last 20 lines of logs
	logOutput, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "20", name).CombinedOutput()

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("容器 %s 状态: %s\n", name, status))
	detail.WriteString(fmt.Sprintf("退出信息: %s\n\n", exitInfo))

	// Check if OOM killed
	if strings.Contains(exitInfo, "true") {
		detail.WriteString("⚠ 容器因 OOM (内存不足) 被杀死！\n")
		detail.WriteString("建议:\n")
		detail.WriteString(fmt.Sprintf("  1. 增加内存限制: docker update --memory=2g %s\n", name))
		detail.WriteString("  2. 检查应用内存泄漏\n")
		detail.WriteString("  3. 查看内存使用: docker stats --no-stream\n")
		detail.WriteString("  4. 检查主机内存: free -h\n\n")
	}

	detail.WriteString("最近日志:\n")
	detail.WriteString(string(logOutput))
	detail.WriteString("\n\n手动重启: docker restart " + name)

	g.eventBus.PublishAlert(types.AlertCritical, "docker",
		fmt.Sprintf("容器已停止: %s", name),
		detail.String(), "container-down-001")
}

// reportContainerUnhealthy reports container health check failure.
func (g *DockerGuard) reportContainerUnhealthy(ctx context.Context, name, status string) {
	// Get health check log
	inspectOutput, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{json .State.Health.Log}}", name).Output()

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("容器 %s 健康检查失败 (%s)\n\n", name, status))

	if err == nil && len(inspectOutput) > 2 {
		detail.WriteString("健康检查日志:\n")
		detail.WriteString(string(inspectOutput))
		detail.WriteString("\n\n")
	}

	detail.WriteString("排查建议:\n")
	detail.WriteString(fmt.Sprintf("  1. 查看容器日志: docker logs --tail 50 %s\n", name))
	detail.WriteString(fmt.Sprintf("  2. 进入容器排查: docker exec -it %s sh\n", name))
	detail.WriteString(fmt.Sprintf("  3. 检查健康检查配置: docker inspect %s | grep -A 20 Health\n", name))
	detail.WriteString("  4. 常见原因:\n")
	detail.WriteString("     - 应用启动慢，健康检查间隔太短\n")
	detail.WriteString("     - 依赖服务不可用 (数据库、Redis等)\n")
	detail.WriteString("     - 端口或文件检查路径配置错误\n\n")
	detail.WriteString(fmt.Sprintf("手动处理: docker restart %s", name))

	g.eventBus.PublishAlert(types.AlertWarning, "docker",
		fmt.Sprintf("容器不健康: %s", name),
		detail.String(), "container-unhealthy-001")
}

// checkOOMKills checks if any containers have been OOM killed recently.
func (g *DockerGuard) checkOOMKills(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "docker", "ps", "-a", "--format",
		"{{.Names}}\t{{.ID}}").Output()
	if err != nil {
		return
	}

	g.mu.Lock()
	oomHistory := g.oomHistory
	g.mu.Unlock()

	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		id := parts[1]

		inspectOutput, err := exec.CommandContext(ctx, "docker", "inspect",
			"--format", "{{.State.OOMKilled}} {{.State.Status}}", id).Output()
		if err != nil {
			continue
		}
		info := strings.TrimSpace(string(inspectOutput))
		fields := strings.Fields(info)
		if len(fields) < 2 {
			continue
		}
		oomKilled := fields[0]

		if oomKilled == "true" {
			g.mu.Lock()
			count := oomHistory[name]
			g.oomHistory[name] = count + 1
			newCount := g.oomHistory[name]
			g.mu.Unlock()

			if newCount <= 3 { // Only alert first few times
				g.eventBus.PublishAlert(types.AlertCritical, "docker",
					fmt.Sprintf("容器OOM: %s (第%d次)", name, newCount),
					fmt.Sprintf("Docker容器 %s 被 OOM Killer 杀死 (第%d次)\n\n"+
						"根本原因分析:\n"+
						"  1. 容器内存限制过低: docker inspect %s | grep Memory\n"+
						"  2. 应用内存泄漏\n"+
						"  3. 主机内存不足\n\n"+
						"解决方案:\n"+
						"  1. 调高内存限制: docker update --memory=2g --memory-swap=2g %s\n"+
						"  2. 检查应用内存使用: docker stats %s\n"+
						"  3. 主机内存: free -h\n"+
						"  4. 检查 dmesg: dmesg | grep -i oom\n\n"+
						"⚠ OOM 可能导致数据损坏，请检查数据完整性后重启:\n"+
						"  docker restart %s",
						name, newCount, name, name, name, name),
					"container-oom-001")
			}
		}
	}
}

// checkResourceUsage checks container resource usage and alerts on high usage.
func (g *DockerGuard) checkResourceUsage(ctx context.Context) {
	// docker stats --no-stream --format
	output, err := exec.CommandContext(ctx, "docker", "stats", "--no-stream",
		"--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		cpuPerc := parts[1]
		memUsage := parts[2]
		memPerc := parts[3]

		// Parse memory percentage
		memPercVal := strings.TrimSuffix(memPerc, "%")
		memPercFloat := 0.0
		fmt.Sscanf(memPercVal, "%f", &memPercFloat)

		if memPercFloat > 90 {
			g.eventBus.PublishAlert(types.AlertWarning, "docker",
				fmt.Sprintf("容器内存过高: %s (%.0f%%)", name, memPercFloat),
				fmt.Sprintf("容器 %s 资源使用:\n  CPU: %s\n  内存: %s (%s)\n\n"+
					"建议:\n"+
					"  1. 调高内存限制: docker update --memory=4g %s\n"+
					"  2. 检查应用内存使用\n"+
					"  3. 检查内存泄漏\n"+
					"  4. 实时监控: docker stats %s",
					name, cpuPerc, memUsage, memPerc, name, name),
				"container-resource-001")
		}

		// Parse CPU percentage
		cpuPercVal := strings.TrimSuffix(cpuPerc, "%")
		cpuPercFloat := 0.0
		fmt.Sscanf(cpuPercVal, "%f", &cpuPercFloat)
		if cpuPercFloat > 90 {
			g.eventBus.PublishAlert(types.AlertWarning, "docker",
				fmt.Sprintf("容器CPU过高: %s (%.0f%%)", name, cpuPercFloat),
				fmt.Sprintf("容器 %s CPU使用 %.0f%%\n\n"+
					"排查:\n"+
					"  1. 进入容器: docker exec -it %s top\n"+
					"  2. 限制CPU: docker update --cpus=2 %s\n"+
					"  3. 检查是否有死循环或计算密集任务",
					name, cpuPercFloat, name, name),
				"container-resource-001")
		}
	}
}

// checkDanglingImages reports dangling images and suggests cleanup (never auto-deletes).
func (g *DockerGuard) checkDanglingImages(ctx context.Context) {
	baotaSafeMode := false
	g.mu.RLock()
	if g.safety != nil {
		baotaSafeMode = g.safety.IsBaotaSafeMode()
	}
	g.mu.RUnlock()

	if baotaSafeMode {
		return // 宝塔模式下跳过
	}

	output, err := exec.CommandContext(ctx, "docker", "images", "-f",
		"dangling=true", "--format", "{{.ID}}\t{{.Size}}").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	count := 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		count++
	}

	if count > 5 {
		g.eventBus.PublishAlert(types.AlertInfo, "docker",
			fmt.Sprintf("悬空镜像过多 (%d个)", count),
			fmt.Sprintf("检测到 %d 个悬空镜像，建议清理:\n"+
				"  docker image prune -f\n\n"+
				"⚠ 请勿清理正在使用的镜像:\n"+
				"  docker images 查看所有镜像\n"+
				"  docker rmi <image-id> 删除特定镜像",
				count),
			"image-prune-001")
	}
}

// autoDiscoverContainers discovers running containers for monitoring.
func (g *DockerGuard) autoDiscoverContainers(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "docker", "ps", "--format",
		"{{.Names}}\t{{.Status}}\t{{.Image}}").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		status := parts[1]
		image := parts[2]

		statusLower := strings.ToLower(status)
		if strings.Contains(statusLower, "unhealthy") {
			g.reportContainerUnhealthy(ctx, name, status)
		} else if strings.Contains(statusLower, "exited") {
			g.reportContainerExited(ctx, name, status)
		}
		_ = image // could log image name in future
	}
}

// AddMonitored adds a container to the monitoring list.
func (g *DockerGuard) AddMonitored(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.monitored = append(g.monitored, name)
}

// SetMaxLogSize provides a suggestion for Docker log size configuration.
// SAFETY: Never modifies daemon.json. Only suggests.
func (g *DockerGuard) SetMaxLogSize(ctx context.Context, maxSize string) {
	g.eventBus.PublishAlert(types.AlertInfo, "docker",
		"日志大小限制建议",
		fmt.Sprintf("建议在 /etc/docker/daemon.json 中设置:\n"+
			"{\n"+
			"  \"log-driver\": \"json-file\",\n"+
			"  \"log-opts\": {\n"+
			"    \"max-size\": \"%s\",\n"+
			"    \"max-file\": \"3\"\n"+
			"  }\n"+
			"}\n\n"+
			"修改后需重启 Docker: sudo systemctl restart docker\n"+
			"⚠ 重启 Docker 会短暂中断所有容器",
			maxSize),
		"docker-log-001")
}

// GetContainerHealthCheck provides health check configuration suggestions.
func (g *DockerGuard) GetContainerHealthCheck(serviceType string) string {
	switch serviceType {
	case "web":
		return `建议在 Dockerfile 或 docker-compose 中添加健康检查:
  HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\
    CMD curl -f http://localhost/ || exit 1`
	case "mysql":
		return `建议在 docker-compose 中添加健康检查:
  healthcheck:
    test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
    interval: 30s
    timeout: 5s
    retries: 3`
	case "redis":
		return `建议在 docker-compose 中添加健康检查:
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 30s
    timeout: 3s
    retries: 3`
	case "postgres":
		return `建议在 docker-compose 中添加健康检查:
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U postgres"]
    interval: 30s
    timeout: 5s
    retries: 3`
	default:
		return `建议添加健康检查:
  HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\
    CMD <健康检查命令> || exit 1`
	}
}
