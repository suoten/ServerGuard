<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>审计日志</span>
            <el-input v-model="searchQuery" placeholder="搜索操作者/对象/原因..." size="small" clearable style="width: 220px" :prefix-icon="Search" />
          </div>
          <el-button text @click="fetchAudit">刷新</el-button>
        </div>
      </template>
      <el-table :data="pagedAudit" v-loading="loading">
        <el-table-column prop="actor" label="操作者" width="120">
          <template #default="{ row }">{{ actorLabel(row.actor) }}</template>
        </el-table-column>
        <el-table-column prop="action" label="操作" width="150">
          <template #default="{ row }">{{ actionLabel(row.action) }}</template>
        </el-table-column>
        <el-table-column prop="target" label="操作对象" width="150" />
        <el-table-column prop="result" label="结果" width="80">
          <template #default="{ row }">
            <el-tag :type="row.result === 'success' ? 'success' : 'danger'">
              {{ row.result === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="原因" show-overflow-tooltip>
          <template #default="{ row }">{{ reasonLabel(row.reason) }}</template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <template #empty>
          <div style="padding: 20px 0">
            <p style="color: #909399">暂无审计日志，所有操作记录将在此显示</p>
          </div>
        </template>
      </el-table>
      <div v-if="filteredAudit.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredAudit.length"
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

const audit = ref<any[]>([])
const loading = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const filteredAudit = computed(() => {
  if (!searchQuery.value) return audit.value
  const q = searchQuery.value.toLowerCase()
  return audit.value.filter((a: any) =>
    a.actor?.toLowerCase().includes(q) ||
    a.action?.toLowerCase().includes(q) ||
    a.target?.toLowerCase().includes(q) ||
    a.reason?.toLowerCase().includes(q)
  )
})

const pagedAudit = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredAudit.value.slice(start, start + pageSize.value)
})

async function fetchAudit() {
  loading.value = true
  try {
    const resp = await axios.get('/api/audit')
    audit.value = resp.data.audit || []
    currentPage.value = 1
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

function actionLabel(action: string): string {
  const labels: Record<string, string> = {
    emergency_stop: '紧急停止',
    emergency_resume: '恢复运行',
    kill: '关闭进程',
    restart: '重启服务',
    ban_ip: '封禁IP',
    unban_ip: '解封IP',
    clean_log: '清理日志',
    rotate_log: '日志轮转',
    renew_cert: '续期证书',
    cve_feed_check: 'CVE漏洞检测',
    security_update_check: '安全补丁检测',
    config_change: '修改配置',
    confirm_finding: '确认安全发现',
    mark_false_positive: '标记误报',
    resolve_alert: '解决告警',
    delete_large_file: '删除大文件',
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
    cert_renew: '证书续期',
    cert_scan: '证书扫描',
    emergency_rollback: '紧急回滚',
    fix_finding: '修复安全发现',
  }
  return labels[action] || action
}

function actorLabel(actor: string): string {
  const labels: Record<string, string> = {
    'system': '系统',
    'api': 'API',
    'auto': '自动',
    'admin': 'admin',
  }
  return labels[actor] || actor || '-'
}

function reasonLabel(reason: string): string {
  const labels: Record<string, string> = {
    'manually triggered via API': '用户手动操作',
    'auto: rule matched': '规则自动触发',
    'auto: cascade protection': '级联保护自动触发',
    'auto: rollback failed': '回滚失败',
    'auto: emergency stop': '紧急停止触发',
    '用户手动操作': '用户手动操作',
    '用户手动重启服务': '用户手动重启服务',
    '用户手动重启（宝塔 init.d）': '用户手动重启（宝塔 init.d）',
    '用户手动重启（init.d 降级）': '用户手动重启（init.d 降级）',
    '用户通过界面手动触发': '用户通过界面手动触发',
    '用户通过界面手动恢复': '用户通过界面手动恢复',
    '用户确认安全发现': '用户确认安全发现',
    '用户标记为误报': '用户标记为误报',
    '用户手动解决告警': '用户手动解决告警',
  }
  return labels[reason] || reason || '-'
}

function formatTime(ts: string) {
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

onMounted(fetchAudit)
</script>
