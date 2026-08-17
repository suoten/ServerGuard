<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>操作日志</span>
            <el-input v-model="searchQuery" placeholder="搜索类型/详情..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
          </div>
          <el-button text @click="fetchLogs">刷新</el-button>
        </div>
      </template>
      <el-table :data="pagedLogs" v-loading="loading">
        <el-table-column prop="action_type" label="操作类型" width="140">
          <template #default="{ row }">{{ actionTypeLabel(row.action_type) }}</template>
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
            <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">Agent 执行修复、封禁等操作后会在此记录</p>
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
import { Search } from '@element-plus/icons-vue'

const logs = ref<any[]>([])
const loading = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const filteredLogs = computed(() => {
  if (!searchQuery.value) return logs.value
  const q = searchQuery.value.toLowerCase()
  return logs.value.filter((l: any) =>
    l.action_type?.toLowerCase().includes(q) ||
    l.message?.toLowerCase().includes(q)
  )
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
    cve_alert: 'CVE漏洞告警',
    security_update: '安全补丁告警',
    reload_nginx: '重载Nginx',
    clean_disk: '清理磁盘',
    alert: '发送告警',
    emergency_stop: '紧急停止',
    emergency_resume: '恢复运行',
    fix_finding: '修复安全发现',
  }
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
