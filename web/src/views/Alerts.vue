<template>
  <div>
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
          <el-radio-group v-model="filterLevel" @change="onFilterChange">
            <el-radio-button label="">全部</el-radio-button>
            <el-radio-button label="critical">严重</el-radio-button>
            <el-radio-button label="error">错误</el-radio-button>
            <el-radio-button label="warning">警告</el-radio-button>
            <el-radio-button label="info">信息</el-radio-button>
          </el-radio-group>
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
            <el-link type="primary" @click="showAlertDetail(row)">{{ row.title }}</el-link>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="120">
          <template #default="{ row }">{{ sourceLabel(row.source) }}</template>
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
import { Bell, Search } from '@element-plus/icons-vue'

const allAlerts = ref<any[]>([])
const loading = ref(false)
const filterLevel = ref('')
const searchQuery = ref('')
const sortBySeverity = ref(true)
const currentPage = ref(1)
const pageSize = ref(10)
const detailVisible = ref(false)
const currentAlert = ref<any>(null)

const severityOrder: Record<string, number> = {
  fatal: 5, critical: 5, error: 4, warning: 3, low: 2, info: 1
}

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
    const resp = await axios.get('/api/alerts')
    allAlerts.value = resp.data.alerts || []
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
  }
  return labels[source] || source
}

function showAlertDetail(row: any) {
  currentAlert.value = row
  detailVisible.value = true
}

onMounted(fetchAlerts)
</script>
