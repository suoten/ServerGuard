package docker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// ContainerGuard provides read-only container inspection and diagnostics.
// SAFETY: Never restarts, prunes, or modifies containers.
type ContainerGuard struct {
	mu         sync.RWMutex
	containers map[string]*ContainerInfo
}

type ContainerInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Image  string `json:"image"`
}

func NewContainerGuard() *ContainerGuard {
	return &ContainerGuard{
		containers: make(map[string]*ContainerInfo),
	}
}

// IsDockerAvailable checks if Docker is installed and accessible.
func (g *ContainerGuard) IsDockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// ListContainers returns all containers with their status.
func (g *ContainerGuard) ListContainers() ([]ContainerInfo, error) {
	cmd := exec.Command("docker", "ps", "-a", "--format",
		"{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var containers []ContainerInfo
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		info := ContainerInfo{
			ID:     parts[0],
			Name:   parts[1],
			Status: parts[2],
			Image:  parts[3],
		}
		containers = append(containers, info)
		g.mu.Lock()
		g.containers[info.ID] = &info
		g.mu.Unlock()
	}
	return containers, nil
}

// InspectContainer returns detailed container info.
func (g *ContainerGuard) InspectContainer(containerID string) (string, error) {
	cmd := exec.Command("docker", "inspect", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// CheckHealthStatus returns the health check status of a container.
func (g *ContainerGuard) CheckHealthStatus(containerID string) (string, error) {
	cmd := exec.Command("docker", "inspect", "--format",
		"{{.State.Health.Status}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// CheckResourceLimits returns the CPU and memory limits for a container.
func (g *ContainerGuard) CheckResourceLimits(containerID string) (cpuLimit string, memLimit string, err error) {
	cmd := exec.Command("docker", "inspect", "--format",
		"{{.HostConfig.NanoCpus}}\t{{.HostConfig.Memory}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(strings.TrimSpace(string(output)), "\t")
	if len(parts) >= 2 {
		cpuLimit = parts[0]
		memLimit = parts[1]
	}
	return cpuLimit, memLimit, nil
}

// CheckOOMKilled checks if a container was OOM killed (read-only).
func (g *ContainerGuard) CheckOOMKilled(containerID string) (bool, error) {
	cmd := exec.Command("docker", "inspect", "--format",
		"{{.State.OOMKilled}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == "true", nil
}

// GetLogs returns the last N lines of container logs (read-only).
func (g *ContainerGuard) GetLogs(containerID string, lines int) (string, error) {
	if lines <= 0 {
		lines = 50
	}
	cmd := exec.Command("docker", "logs", "--tail",
		fmt.Sprintf("%d", lines), containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GetRestartCount returns the number of times a container has restarted.
func (g *ContainerGuard) GetRestartCount(containerID string) (int, error) {
	cmd := exec.Command("docker", "inspect", "--format",
		"{{.RestartCount}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	var count int
	fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &count)
	return count, nil
}

// PruneAdvice generates cleanup suggestions without executing them.
// SAFETY: Never executes prune commands. Only returns suggestions.
func (g *ContainerGuard) PruneAdvice() string {
	return `Docker 清理建议 (手动执行):

1. 清理已停止的容器:
   docker container prune -f
   ⚠ 确认没有需要保留的已停止容器

2. 清理悬空镜像:
   docker image prune -f
   (只清理未被任何容器使用的悬空镜像)

3. 清理未使用的镜像:
   docker image prune -a -f
   ⚠ 会删除所有未被容器使用的镜像

4. 清理未使用的网络:
   docker network prune -f

5. 清理未使用的卷:
   docker volume prune -f
   ⚠⚠ 卷可能包含重要数据！请逐个检查:
   docker volume ls
   docker volume inspect <volume-name>

6. 一键清理 (除卷):
   docker system prune -f

7. 完全清理 (含卷, 极度危险):
   docker system prune -a --volumes -f
   ⚠⚠⚠ 会删除所有未使用的数据卷，可能导致数据丢失！`
}

// ResourceLimitAdvice generates resource limit suggestions for a container.
func (g *ContainerGuard) ResourceLimitAdvice(containerName string, cpuLimit, memLimit string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("容器 %s 资源限制分析:\n", containerName))

	// CPU limit
	if cpuLimit == "0" {
		sb.WriteString("  CPU: 无限制 (建议设置)\n")
		sb.WriteString(fmt.Sprintf("    docker update --cpus=2 %s\n", containerName))
	} else {
		cpus := float64(0)
		fmt.Sscanf(cpuLimit, "%f", &cpus)
		if cpus > 0 {
			sb.WriteString(fmt.Sprintf("  CPU: %.1f 核\n", cpus/1e9))
		}
	}

	// Memory limit
	if memLimit == "0" {
		sb.WriteString("  内存: 无限制 (建议设置)\n")
		sb.WriteString(fmt.Sprintf("    docker update --memory=2g --memory-swap=2g %s\n", containerName))
	} else {
		memBytes := int64(0)
		fmt.Sscanf(memLimit, "%d", &memBytes)
		if memBytes > 0 {
			sb.WriteString(fmt.Sprintf("  内存: %.1f GB\n", float64(memBytes)/1024/1024/1024))
		}
	}

	sb.WriteString("\n建议:\n")
	sb.WriteString("  1. 为每个容器设置 CPU 和内存限制\n")
	sb.WriteString("  2. 使用 docker-compose 时在 deploy.resources 中定义\n")
	sb.WriteString("  3. 监控实际使用: docker stats\n")
	sb.WriteString("  4. 不要过度分配 (所有容器限制之和 < 主机资源 * 0.8)")

	return sb.String()
}

// LogLimitAdvice generates Docker log configuration suggestions.
func (g *ContainerGuard) LogLimitAdvice() string {
	return `Docker 日志限制建议:

在 /etc/docker/daemon.json 中配置全局日志限制:
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}

或对单个容器设置:
  docker run --log-driver json-file \\
    --log-opt max-size=50m \\
    --log-opt max-file=3 \\
    <image>

修改 daemon.json 后需重启 Docker:
  sudo systemctl restart docker
⚠ 重启会短暂中断所有容器

建议同时配置日志轮转监控:
  docker inspect <container> | grep LogPath
  检查日志文件大小: ls -lh $(docker inspect <container> | grep LogPath | cut -d'"' -f4)`
}

// NetworkChecker checks Docker network configuration.
type NetworkChecker struct {
	mu sync.RWMutex
}

func NewNetworkChecker() *NetworkChecker {
	return &NetworkChecker{}
}

// ListNetworks returns all Docker networks.
func (c *NetworkChecker) ListNetworks() ([]string, error) {
	cmd := exec.Command("docker", "network", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Scope}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var networks []string
	for _, line := range strings.Split(string(output), "\n") {
		if line != "" {
			networks = append(networks, line)
		}
	}
	return networks, nil
}

// CheckPortConflicts detects potential port conflicts between containers.
func (c *NetworkChecker) CheckPortConflicts(ctx context.Context) []string {
	output, err := exec.CommandContext(ctx, "docker", "ps", "--format",
		"{{.Names}}\t{{.Ports}}").Output()
	if err != nil {
		return nil
	}

	portMap := make(map[string][]string)
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		ports := parts[1]
		// Extract host port bindings
		for _, port := range strings.Split(ports, ", ") {
			if idx := strings.Index(port, "->"); idx > 0 {
				hostPort := strings.TrimSpace(port[:idx])
				if strings.Contains(hostPort, ":") {
					hostPort = hostPort[strings.LastIndex(hostPort, ":")+1:]
				}
				portMap[hostPort] = append(portMap[hostPort], name)
			}
		}
	}

	var conflicts []string
	for port, containers := range portMap {
		if len(containers) > 1 {
			conflicts = append(conflicts, fmt.Sprintf("端口 %s 被 %d 个容器使用: %s",
				port, len(containers), strings.Join(containers, ", ")))
		}
	}
	return conflicts
}
