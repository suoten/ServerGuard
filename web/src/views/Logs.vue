<template>
  <div>
    <!-- 自动处理摘要 -->
    <el-card v-if="logStats.total > 0" shadow="hover" style="margin-bottom: 16px">
      <div class="log-stats-row">
        <span class="log-stats-title">
          <el-icon color="#52c41a"><CircleCheck /></el-icon>
          操作日志概览
          <el-tag size="small" type="info" style="margin-left: 6px">{{ logStats.total }} 条记录</el-tag>
        </span>
        <div class="log-stats-items">
          <span class="log-stats-item">
            <el-icon color="#1890ff"><Tools /></el-icon>
            自动执行 <strong>{{ logStats.autoCount }}</strong> 次
          </span>
          <span class="log-stats-item">
            <el-icon color="#909399"><User /></el-icon>
            手动触发 <strong>{{ logStats.manualCount }}</strong> 次
          </span>
          <span class="log-stats-item">
            成功率 <strong :style="{ color: logStats.successRate >= 80 ? '#52c41a' : '#f56c6c' }">{{ logStats.successRate }}%</strong>
          </span>
        </div>
      </div>
    </el-card>

    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>操作日志</span>
            <el-input v-model="searchQuery" placeholder="搜索类型/详情..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
          </div>
          <el-radio-group v-model="filterSource" size="small">
            <el-radio-button value="">全部</el-radio-button>
            <el-radio-button value="auto">自动执行</el-radio-button>
            <el-radio-button value="manual">手动触发</el-radio-button>
          </el-radio-group>
        </div>
      </template>
      <el-table :data="pagedLogs" v-loading="loading">
        <el-table-column prop="action_type" label="操作类型" width="140">
          <template #default="{ row }">
            <div style="display: flex; align-items: center; gap: 4px">
              <span>{{ actionTypeLabel(row.action_type) }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="触发方式" width="100">
          <template #default="{ row }">
            <el-tag v-if="isAutoAction(row.action_type)" type="primary" size="small" effect="plain">
              <el-icon style="margin-right: 2px"><Tools /></el-icon>自动
            </el-tag>
            <el-tag v-else type="info" size="small" effect="plain">
              <el-icon style="margin-right: 2px"><User /></el-icon>手动
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.target || (row.action?.params?.target) || '-' }}</template>
        </el-table-column>
        <el-table-column prop="success" label="结果" width="80">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'">{{ row.success ? '成功' : '失败' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="详情" show-overflow-tooltip />
        <el-table-column prop="duration" label="耗时" width="100">
          <template #default="{ row }">{{ formatDuration(row.duration) }}</template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <template #empty>
          <div style="padding: 20px 0">
            <p style="color: #909399">暂无操作日志</p>
            <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">
              ServerGuard 自动执行修复、清理、封禁等操作后会在此记录，无需人工干预
            </p>
          </div>
        </template>
      </el-table>
      <div v-if="filteredLogs.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredLogs.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { Search, CircleCheck, Tools, User } from '@element-plus/icons-vue'

const logs = ref<any[]>([])
const loading = ref(false)
const searchQuery = ref('')
const filterSource = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

// 自动执行的动作类型集合
const autoActionTypes = new Set([
  'kill', 'sigterm', 'sigkill', 'restart', 'ban_ip', 'unban_ip',
  'clean_log', 'rotate_log', 'renew_cert', 'cert_renew', 'cert_scan',
  'cve_alert', 'cve_feed_check', 'security_update', 'security_update_check',
  'reload_nginx', 'clean_disk', 'alert', 'auto_fix_finding',
  'emergency_stop', 'emergency_resume', 'emergency_rollback',
  'scan_websecurity', 'scan_vulnscan', 'scan_serversecurity', 'scan_attackwarn',
])

function isAutoAction(type: string): boolean {
  return autoActionTypes.has(type)
}

// 日志统计
const logStats = computed(() => {
  const total = logs.value.length
  const autoCount = logs.value.filter((l: any) => isAutoAction(l.action_type)).length
  const manualCount = total - autoCount
  const successCount = logs.value.filter((l: any) => l.success).length
  const successRate = total > 0 ? Math.round((successCount / total) * 100) : 100
  return { total, autoCount, manualCount, successRate }
})

const filteredLogs = computed(() => {
  let result = logs.value
  if (filterSource.value === 'auto') {
    result = result.filter((l: any) => isAutoAction(l.action_type))
  } else if (filterSource.value === 'manual') {
    result = result.filter((l: any) => !isAutoAction(l.action_type))
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter((l: any) =>
      l.action_type?.toLowerCase().includes(q) ||
      l.message?.toLowerCase().includes(q)
    )
  }
  return result
})

const pagedLogs = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredLogs.value.slice(start, start + pageSize.value)
})

async function fetchLogs() {
  loading.value = true
  try {
    const resp = await axios.get('/api/logs')
    logs.value = resp.data.actions || []
    currentPage.value = 1
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

function actionTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    kill: '关闭进程',
    sigterm: '关闭进程',
    sigkill: '强制关闭',
    restart: '重启服务',
    ban_ip: '封禁IP',
    unban_ip: '解封IP',
    clean_log: '清理日志',
    rotate_log: '日志轮转',
    renew_cert: '续期证书',
    cert_renew: '证书续期',
    cert_scan: '证书扫描',
    cve_alert: 'CVE漏洞告警',
    cve_feed_check: 'CVE漏洞检测',
    security_update: '安全补丁告警',
    security_update_check: '安全补丁检测',
    reload_nginx: '重载Nginx',
    clean_disk: '清理磁盘',
    alert: '发送告警',
    emergency_stop: '紧急停止',
    emergency_resume: '恢复运行',
    emergency_rollback: '紧急回滚',
    fix_finding: '修复安全发现',
    auto_fix_finding: '自动修复',
    confirm_finding: '确认安全发现',
    mark_false_positive: '标记误报',
    resolve_alert: '解决告警',
    delete_large_file: '删除大文件',
    batch_delete_large_file: '批量删除大文件',
    config_change: '修改配置',
    save_settings: '保存设置',
    add_rule: '添加规则',
    update_rule: '更新规则',
    toggle_rule: '切换规则',
    delete_rule: '删除规则',
    add_guard: '添加守护',
    remove_guard: '移除守护',
    add_probe_site: '添加监控站点',
    delete_probe_site: '删除监控站点',
    scan_websecurity: '网站安全扫描',
    scan_vulnscan: '漏洞扫描',
    scan_serversecurity: '服务器安全扫描',
    scan_attackwarn: '攻击预警扫描',
    create_maintenance_window: '创建维护窗口',
    delete_maintenance_window: '删除维护窗口',
    incident_ack: '确认事件',
    create_user: '创建用户',
    update_user: '更新用户',
    reset_password: '重置密码',
    delete_user: '删除用户',
    ghost_scan: '幽灵文件扫描',
    nice: '调整优先级',
    run_script: '执行脚本',
    snapshot: '创建快照',
    killed: '已终止',
    suggested: '建议操作',
  }
  // 处理动态前缀的 action
  if (type.startsWith('agent_command:')) return '远程命令: ' + type.substring('agent_command:'.length)
  if (type.startsWith('import:')) return '导入: ' + type.substring('import:'.length)
  return labels[type] || type || '-'
}

function formatTime(ts: string) {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

function formatDuration(d: any): string {
  if (!d || d === 0) return '-'
  // d 可能是毫秒数（后端返回 duration.Milliseconds()）
  const ms = Number(d)
  if (!isNaN(ms)) {
    if (ms < 1) return '<1ms'
    if (ms < 1000) return `${ms}ms`
    return `${(ms / 1000).toFixed(1)}s`
  }
  // 兼容旧格式
  const str = String(d)
  if (str.includes('ms') || str.includes('s')) return str
  return str
}

onMounted(fetchLogs)
</script>

<style scoped>
.log-stats-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 16px;
}
.log-stats-title {
  font-weight: 600;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.log-stats-items {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 14px;
  flex: 1;
}
.log-stats-item {
  font-size: 13px;
  color: #606266;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.log-stats-item strong {
  font-size: 15px;
  font-weight: 700;
  color: #303133;
}
</style>
