package tuning

import (
	"fmt"
	"strings"
)

type LoadTypeTuner struct{}

func NewLoadTypeTuner() *LoadTypeTuner { return &LoadTypeTuner{} }

type LoadType string

const (
	LoadStreaming LoadType = "streaming"
	LoadDatabase  LoadType = "database"
	LoadAI        LoadType = "ai"
	LoadWeb       LoadType = "web"
	LoadGeneral   LoadType = "general"
)

type TuningAdvice struct {
	LoadType  LoadType          `json:"load_type"`
	SysctlPatches map[string]string `json:"sysctl_patches"`
	Reason    string            `json:"reason"`
}

func (t *LoadTypeTuner) GenerateAdvice(loadType LoadType) *TuningAdvice {
	advice := &TuningAdvice{
		LoadType:       loadType,
		SysctlPatches: make(map[string]string),
	}

	switch loadType {
	case LoadStreaming:
		advice.SysctlPatches["net.core.rmem_max"] = "16777216"
		advice.SysctlPatches["net.core.wmem_max"] = "16777216"
		advice.SysctlPatches["net.ipv4.tcp_rmem"] = "4096 87380 16777216"
		advice.SysctlPatches["net.ipv4.tcp_wmem"] = "4096 65536 16777216"
		advice.SysctlPatches["net.ipv4.tcp_congestion_control"] = "bbr"
		advice.Reason = "流媒体服务需要大缓冲区和BBR拥塞控制"
	case LoadDatabase:
		advice.SysctlPatches["vm.swappiness"] = "1"
		advice.SysctlPatches["vm.dirty_ratio"] = "15"
		advice.SysctlPatches["vm.dirty_background_ratio"] = "5"
		advice.SysctlPatches["fs.file-max"] = "655350"
		advice.Reason = "数据库需要低swappiness减少交换、快速刷盘"
	case LoadAI:
		advice.SysctlPatches["vm.swappiness"] = "10"
		advice.SysctlPatches["kernel.shmmax"] = "68719476736"
		advice.SysctlPatches["kernel.shmall"] = "4294967296"
		advice.Reason = "AI需要大共享内存和适度交换"
	case LoadWeb:
		advice.SysctlPatches["net.ipv4.tcp_tw_reuse"] = "1"
		advice.SysctlPatches["net.ipv4.tcp_max_tw_buckets"] = "5000"
		advice.SysctlPatches["net.core.somaxconn"] = "4096"
		advice.SysctlPatches["net.ipv4.tcp_fastopen"] = "3"
		advice.Reason = "Web服务需要快速连接复用和高并发"
	default:
		advice.SysctlPatches["vm.swappiness"] = "60"
		advice.Reason = "通用配置"
	}

	return advice
}

func (t *LoadTypeTuner) GenerateSysctlFile(advice *TuningAdvice) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# ServerGuard tuning for %s\n", advice.LoadType))
	sb.WriteString(fmt.Sprintf("# %s\n", advice.Reason))
	sb.WriteString("# 请审核后手动应用: sysctl -p\n\n")
	for key, value := range advice.SysctlPatches {
		sb.WriteString(fmt.Sprintf("%s = %s\n", key, value))
	}
	return sb.String()
}

func (t *LoadTypeTuner) DetectLoadType() LoadType {
	return LoadGeneral
}