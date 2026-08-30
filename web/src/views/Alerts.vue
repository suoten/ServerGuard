<template>
  <div>
    <!-- 自动修复概览条 -->
    <el-card v-if="autoFixStats.total > 0" shadow="hover" style="margin-bottom: 16px">
      <div class="auto-fix-summary">
        <span class="auto-fix-title">
          <el-icon color="#52c41a"><CircleCheck /></el-icon>
          ServerGuard 已自动处理
          <el-tag size="small" type="success" style="margin-left: 6px">{{ autoFixStats.total }} 条告警</el-tag>
        </span>
        <div class="auto-fix-items">
          <span v-if="autoFixStats.autoResolved > 0" class="auto-fix-item">
            <el-icon color="#52c41a"><Check /></el-icon>
            自动修复 <strong>{{ autoFixStats.autoResolved }}</strong> 条
          </span>
          <span v-if="autoFixStats.acked > 0" class="auto-fix-item">
            <el-icon color="#1890ff"><BellFilled /></el-icon>
            自动确认 <strong>{{ autoFixStats.acked }}</strong> 条
          </span>
          <span v-if="autoFixStats.pending > 0" class="auto-fix-item">
            <el-icon color="#faad14"><Clock /></el-icon>
            待处理 <strong>{{ autoFixStats.pending }}</strong> 条
          </span>
          <span class="auto-fix-item auto-fix-link" @click="$router.push('/logs')">
            查看自动处理记录 <el-icon><ArrowRight /></el-icon>
          </span>
        </div>
      </div>
    </el-card>

    <!-- 级别筛选卡片 -->
    <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap">
      <div
        v-for="tab in levelTabs"
        :key="tab.key"
        @click="filterLevel = tab.key; onFilterChange()"
        :style="{
          cursor: 'pointer',
          flex: '1 1 100px',
          minWidth: '100px',
          padding: '10px 14px',
          borderRadius: '8px',
          border: filterLevel === tab.key ? `2px solid ${tab.color}` : '1px solid #e4e7ed',
          background: filterLevel === tab.key ? tab.bg : '#fff',
          transition: 'all 0.2s',
          textAlign: 'center',
        }"
      >
        <div :style="{ fontSize: '22px', fontWeight: 700, color: tab.color, lineHeight: '1.2' }">
          <CountUp :value="tab.count" />
        </div>
        <div style="font-size: 12px; color: #909399; margin-top: 4px">{{ tab.label }}</div>
      </div>
    </div>

    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>告警中心</span>
            <el-input
              v-model="searchQuery"
              placeholder="搜索标题/内容/来源..."
              size="small"
              clearable
              style="width: 220px"
              :prefix-icon="Search"
            />
          </div>
          <el-button :type="sortBySeverity ? 'danger' : 'default'" size="small" plain @click="sortBySeverity = !sortBySeverity">
            {{ sortBySeverity ? '🔴 按严重程度' : '🕐 按时间' }}
          </el-button>
        </div>
      </template>
      <el-table :data="pagedAlerts" style="width: 100%" v-loading="loading">
        <el-table-column prop="level" label="级别" width="80">
          <template #default="{ row }">
            <el-tag :type="alertType(row.level)" size="small">{{ alertLabel(row.level) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="标题" show-overflow-tooltip>
          <template #default="{ row }">
            <el-link type="primary" @click="showAlertDetail(row)">
              <el-icon v-if="isAutoFixable(row.source)" color="#52c41a" style="margin-right: 4px" title="此告警可被自动修复"><Tools /></el-icon>
              {{ row.title }}
            </el-link>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="120">
          <template #default="{ row }">{{ sourceLabel(row.source) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.acknowledged" type="success" size="small" effect="plain">已确认</el-tag>
            <el-tag v-else-if="isAutoFixable(row.source)" type="warning" size="small" effect="plain">可自动修复</el-tag>
            <el-tag v-else type="info" size="small" effect="plain">待处理</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button size="small" @click="showAlertDetail(row)">详情</el-button>
            <el-button size="small" type="success" @click="resolveAlert(row.id)">解决</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 20px 0">
            <el-icon style="font-size: 40px; color: #c0c4cc; margin-bottom: 10px"><Bell /></el-icon>
            <p style="color: #909399">暂无告警，系统运行正常</p>
            <p v-if="autoFixStats.total > 0" style="color: #52c41a; font-size: 13px; margin-top: 8px">
              ServerGuard 在过去 24 小时已自动处理 {{ autoFixStats.total }} 条告警
            </p>
          </div>
        </template>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredAlerts.length"
          layout="total, sizes, prev, pager, next"
          @size-change="onPageSizeChange"
          @current-change="onPageChange"
        />
      </div>
      </el-card>

    <!-- 告警详情对话框 -->
    <el-dialog v-model="detailVisible" title="告警详情" width="600px">
      <el-descriptions :column="1" border v-if="currentAlert">
        <el-descriptions-item label="级别">
          <el-tag :type="alertType(currentAlert.level)" size="small">{{ alertLabel(currentAlert.level) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="标题">{{ currentAlert.title }}</el-descriptions-item>
        <el-descriptions-item label="来源">{{ sourceLabel(currentAlert.source) }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(currentAlert.timestamp) }}</el-descriptions-item>
        <el-descriptions-item label="详情" v-if="currentAlert.message">{{ currentAlert.message }}</el-descriptions-item>
        <el-descriptions-item label="规则ID" v-if="currentAlert.rule_id">{{ currentAlert.rule_id }}</el-descriptions-item>
        <el-descriptions-item label="标签" v-if="currentAlert.labels && Object.keys(currentAlert.labels).length">
          <el-tag v-for="(v, k) in currentAlert.labels" :key="k" size="small" style="margin-right: 4px">{{ k }}: {{ v }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <!-- 自动修复能力提示 -->
      <el-alert
        v-if="currentAlert && isAutoFixable(currentAlert.source)"
        type="success"
        :closable="false"
        show-icon
        style="margin-top: 16px"
      >
        <template #title>此告警可被 ServerGuard 自动修复</template>
        <template #default>
          {{ autoFixDescription(currentAlert.source) }}
          <span v-if="currentAlert.acknowledged" style="margin-left: 8px; color: #52c41a; font-weight: 600">
            ✓ 已自动确认并处理
          </span>
        </template>
      </el-alert>

      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
        <el-button type="success" @click="resolveAlert(currentAlert.id); detailVisible = false">标记解决</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { Bell, Search, CircleCheck, Check, BellFilled, Clock, ArrowRight, Tools } from '@element-plus/icons-vue'
import CountUp from '../components/CountUp.vue'

const allAlerts = ref<any[]>([])
const loading = ref(false)
const filterLevel = ref('')
const searchQuery = ref('')
const sortBySeverity = ref(true)
const currentPage = ref(1)
const pageSize = ref(10)
const detailVisible = ref(false)
const currentAlert = ref<any>(null)
const safetyActions = ref<any[]>([])

const severityOrder: Record<string, number> = {
  fatal: 5, critical: 5, error: 4, warning: 3, low: 2, info: 1
}

// 可自动修复的来源
const autoFixableSources = new Set([
'resource', 'service', 'log', 'network', 'system', 'cert', 'docker', 'config', 'database', 'storage', 'traffic', 'devops', 'datagovern', 'attackwarn'
])

function isAutoFixable(source: string): boolean {
  return autoFixableSources.has(source)
}

function autoFixDescription(source: string): string {
  const descriptions: Record<string, string> = {
    resource: '资源超限时自动清理磁盘空间、关闭高资源占用进程',
    service: '服务异常时自动重启、自动恢复守护进程',
    log: '日志暴涨时自动截断、轮转、清理过期日志',
    network: '网络异常时自动排查 DNS、重置连接',
    system: '系统异常时自动修复配置、清理临时文件',
    cert: '证书即将过期时自动续期并重载 Web 服务',
    docker: '容器异常时自动重启、清理无用镜像',
    config: '配置异常时自动回滚到上一版本',
    database: '数据库异常时自动优化、清理慢查询',
    storage: '存储空间不足时自动清理大文件和幽灵文件',
  }
  return descriptions[source] || 'ServerGuard 会自动处理此类型的问题'
}

// 自动修复统计
const autoFixStats = computed(() => {
  const total = allAlerts.value.length
  const acked = allAlerts.value.filter((a: any) => a.acknowledged).length
  const autoResolved = allAlerts.value.filter((a: any) => a.acknowledged && isAutoFixable(a.source)).length
  const pending = allAlerts.value.filter((a: any) => !a.acknowledged).length
  return { total: total + safetyActions.value.length, autoResolved, acked, pending }
})

const levelStats = computed(() => {
  const stats: Record<string, number> = { critical: 0, error: 0, warning: 0, info: 0 }
  for (const a of allAlerts.value) {
    if (stats[a.level] !== undefined) stats[a.level]++
  }
  return stats
})

const levelTabs = computed(() => [
  { key: '', label: '全部', count: allAlerts.value.length, color: '#409eff', bg: '#ecf5ff' },
  { key: 'critical', label: '严重', count: levelStats.value.critical, color: '#f56c6c', bg: '#fef0f0' },
  { key: 'error', label: '错误', count: levelStats.value.error, color: '#f56c6c', bg: '#fef0f0' },
  { key: 'warning', label: '警告', count: levelStats.value.warning, color: '#e6a23c', bg: '#fdf6ec' },
  { key: 'info', label: '信息', count: levelStats.value.info, color: '#909399', bg: '#f4f4f5' },
])

const filteredAlerts = computed(() => {
  let result = allAlerts.value
  if (filterLevel.value) {
    result = result.filter((a: any) => a.level === filterLevel.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter((a: any) =>
      a.title?.toLowerCase().includes(q) ||
      a.message?.toLowerCase().includes(q) ||
      a.source?.toLowerCase().includes(q)
    )
  }
  if (sortBySeverity.value) {
    result = [...result].sort((a: any, b: any) => {
      const diff = (severityOrder[b.level] || 0) - (severityOrder[a.level] || 0)
      if (diff !== 0) return diff
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    })
  }
  return result
})

const pagedAlerts = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredAlerts.value.slice(start, start + pageSize.value)
})

function onFilterChange() {
  currentPage.value = 1
}

function onPageSizeChange() {
  currentPage.value = 1
}

function onPageChange() {
  // currentPage already updated by v-model
}

async function fetchAlerts() {
  loading.value = true
  try {
    const [alertsResp, safetyResp] = await Promise.all([
      axios.get('/api/alerts'),
      axios.get('/api/safety'),
    ])
    allAlerts.value = alertsResp.data.alerts || []
    safetyActions.value = safetyResp.data.recent_actions || []
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

async function resolveAlert(id: string) {
  try {
    await axios.post(`/api/alerts/${id}/resolve`)
    await fetchAlerts()
  } catch (err) {
    // ignore
  }
}

function alertType(level: string) {
  const types: Record<string, string> = {
    info: 'info', warning: 'warning', error: 'danger', critical: 'danger', fatal: 'danger'
  }
  return types[level] || 'info'
}

function alertLabel(level: string) {
  const labels: Record<string, string> = {
    info: '信息', warning: '警告', error: '错误', critical: '严重', fatal: '致命'
  }
  return labels[level] || level
}

function formatTime(ts: string) {
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

function sourceLabel(source: string) {
  const labels: Record<string, string> = {
    vulnscan: '漏洞扫描',
    serversecurity: '服务器安全',
    websecurity: '网站安全',
    attackwarn: '攻击预警',
    resource: '资源守护',
    service: '服务守护',
    security: '安全防护',
    log: '日志防护',
    network: '网络守护',
    system: '系统守护',
    cert: '证书守护',
    docker: '容器守护',
    config: '配置守护',
    database: '数据库守护',
    storage: '存储管理',
    baota: '宝塔面板',
    agent: 'Agent',
    baseline: '基线检测',
    forecast: '趋势预测',
    correlation: '故障关联',
    traffic: '流量守护',
    ai: 'AI 异常检测',
    tuning: '调优顾问',
    devops: 'DevOps',
    datagovern: '数据治理',
    hub: '中心管理',
    apm: 'APM 分析',
    netquality: '网络质量',
    anomaly: '异常检测',
    healthscore: '健康评分',
    knowledge: '知识库',
    probe: '站点探测',
    heartbeat: '心跳',
    posture: '系统态势',
    notifier: '通知系统',
    upgrade: '版本升级',
    nginx: 'Nginx',
    redis: 'Redis',
    mysql: 'MySQL',
    slowquery: '慢查询',
    backup: '备份守护',
    fd: '文件描述符',
    dns: 'DNS',
    clock: '时钟同步',
  }
  return labels[source] || source
}

function showAlertDetail(row: any) {
  currentAlert.value = row
  detailVisible.value = true
}

onMounted(fetchAlerts)
</script>

<style scoped>
.auto-fix-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 16px;
}
.auto-fix-title {
  font-weight: 600;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.auto-fix-items {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 14px;
  flex: 1;
}
.auto-fix-item {
  font-size: 13px;
  color: #606266;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}
.auto-fix-item strong {
  font-size: 15px;
  font-weight: 700;
  color: #303133;
}
.auto-fix-link {
  color: #409eff;
  cursor: pointer;
  margin-left: auto;
}
.auto-fix-link:hover {
  opacity: 0.8;
}
</style>
