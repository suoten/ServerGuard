<template>
  <div class="findings-page">
    <!-- 自动扫描状态提示 -->
    <el-card style="margin-bottom: 20px">
      <template #header>
        <div class="card-header">
          <span>自动安全扫描</span>
          <el-tag type="success" size="small">每 1 小时自动扫描</el-tag>
        </div>
      </template>
<el-alert type="info" :closable="false" show-icon>
Agent 已自动执行四项安全扫描（服务器安全、漏洞扫描、网站安全、攻击预警），下方列表展示自动发现的结果。
如需立即触发扫描，可点击右侧按钮。
</el-alert>
      <div class="scan-buttons" style="margin-top: 15px">
        <el-button type="primary" size="small" @click="triggerScan('serversecurity')" :loading="scanning==='serversecurity'">
          立即扫描·服务器安全
        </el-button>
        <el-button type="warning" size="small" @click="triggerScan('vulnscan')" :loading="scanning==='vulnscan'">
          立即扫描·漏洞
        </el-button>
        <el-button type="danger" size="small" @click="triggerScan('websecurity')" :loading="scanning==='websecurity'">
          立即扫描·网站安全
        </el-button>
        <el-button type="success" size="small" @click="triggerScan('attackwarn')" :loading="scanning==='attackwarn'">
          立即扫描·攻击预警
        </el-button>
      </div>
      <el-alert v-if="scanResult" :title="scanResult.message" :type="scanResult.type" show-icon closable @close="scanResult = null" style="margin-top: 15px" />
    </el-card>

    <!-- 统计卡片 -->
    <el-row :gutter="16" style="margin-bottom: 20px">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card stat-server">
          <div class="stat-content">
            <div class="stat-icon">🛡️</div>
            <div class="stat-body">
              <div class="stat-value">{{ statsByScanner.serversecurity || 0 }}</div>
              <div class="stat-label">服务器安全</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card stat-vuln">
          <div class="stat-content">
            <div class="stat-icon">🐛</div>
            <div class="stat-body">
              <div class="stat-value">{{ statsByScanner.vulnscan || 0 }}</div>
              <div class="stat-label">漏洞扫描</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card stat-web">
          <div class="stat-content">
            <div class="stat-icon">🌐</div>
            <div class="stat-body">
              <div class="stat-value">{{ statsByScanner.websecurity || 0 }}</div>
              <div class="stat-label">网站安全</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card stat-attack">
          <div class="stat-content">
            <div class="stat-icon">⚠️</div>
            <div class="stat-body">
              <div class="stat-value">{{ statsByScanner.attackwarn || 0 }}</div>
              <div class="stat-label">攻击预警</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 自动发现结果列表 -->
    <el-card>
      <template #header>
        <div class="card-header">
          <span>安全发现项 <el-tag size="small" type="info">共 {{ total }} 条</el-tag></span>
          <div class="header-actions">
            <el-input v-model="searchQuery" placeholder="搜索标题/目标/描述..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
            <el-button :type="sortBySeverity ? 'danger' : 'default'" size="small" plain @click="sortBySeverity = !sortBySeverity">
              {{ sortBySeverity ? '🔴 按严重程度' : '🕐 按时间' }}
            </el-button>
            <el-select v-model="filterScanner" placeholder="扫描器" clearable size="small" style="width: 140px" @change="onFilterChange">
              <el-option label="全部" value="" />
              <el-option label="服务器安全" value="serversecurity" />
              <el-option label="漏洞扫描" value="vulnscan" />
              <el-option label="网站安全" value="websecurity" />
              <el-option label="攻击预警" value="attackwarn" />
            </el-select>
            <el-select v-model="filterSeverity" placeholder="严重程度" clearable size="small" style="width: 120px" @change="onFilterChange">
              <el-option label="全部" value="" />
              <el-option label="严重" value="critical" />
              <el-option label="高" value="high" />
              <el-option label="中" value="medium" />
              <el-option label="低" value="low" />
              <el-option label="信息" value="info" />
            </el-select>
            <el-button type="primary" size="small" @click="generateReport">生成报告</el-button>
          </div>
        </div>
      </template>

      <el-table :data="pagedFindings" stripe v-loading="loading" style="width: 100%">
        <el-table-column label="扫描器" width="120">
          <template #default="{ row }">
            <el-tag :type="scannerTagType(row.scanner)" size="small">{{ scannerLabel(row.scanner) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="标题" show-overflow-tooltip>
          <template #default="{ row }">
            {{ formatFindingTitle(row.title) }}
            <el-tag v-if="isIntelFinding(row)" type="warning" size="small" style="margin-left:6px" title="该漏洞由外部威胁情报补充">情报</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)">{{ severityLabel(row.severity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target" label="目标" show-overflow-tooltip width="200" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="检测时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" @click="showDetail(row)">详情</el-button>
            <el-button v-if="canAutoFix(row)" size="small" type="warning" @click="autoFix(row.id)" :loading="fixingId === row.id" :disabled="row.status === 'fixed'">🔧 修复</el-button>
            <el-button size="small" type="success" @click="confirmFinding(row.id)" :disabled="row.status !== 'open'">确认</el-button>
            <el-button size="small" type="warning" @click="markFalsePositive(row.id)" :disabled="row.status === 'false_positive'">误报</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 30px 0; text-align: center">
            <el-icon style="font-size: 32px; color: #c0c4cc; margin-bottom: 10px"><Loading /></el-icon>
            <p style="color: #909399; margin: 0">Agent 正在自动扫描中，请稍候...（启动后约 3 秒开始首次扫描）</p>
            <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">扫描完成后将自动显示结果，无需手动操作</p>
          </div>
        </template>
      </el-table>

      <!-- 分页 -->
      <div style="margin-top: 16px; display: flex; justify-content: flex-end" v-if="total > 0">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <!-- 详情弹窗 -->
    <el-dialog v-model="detailVisible" title="发现详情与修复指南" width="750px">
      <div v-if="currentDetail">
        <!-- 基本信息 -->
        <el-descriptions :column="1" border>
          <el-descriptions-item label="扫描器">
            <el-tag :type="scannerTagType(currentDetail.scanner)" size="small">{{ scannerLabel(currentDetail.scanner) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="标题">{{ currentDetail.title }}</el-descriptions-item>
          <el-descriptions-item label="严重程度">
            <el-tag :type="severityType(currentDetail.severity)">{{ severityLabel(currentDetail.severity) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="目标">{{ currentDetail.target }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType(currentDetail.status)">{{ statusLabel(currentDetail.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="检测时间">{{ formatTime(currentDetail.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <!-- 问题描述 -->
        <el-divider content-position="left">问题描述</el-divider>
        <div style="padding: 0 10px">
          <p style="color: #606266; line-height: 1.8; margin: 0">{{ currentDetail.description || '无描述信息' }}</p>
          <p v-if="currentDetail.detail" style="color: #909399; font-size: 13px; line-height: 1.8; margin-top: 10px; white-space: pre-wrap">{{ currentDetail.detail }}</p>
        </div>

        <!-- 修复指南 -->
        <el-divider content-position="left">
          <span style="color: #67c23a; font-weight: bold">🔧 修复指南</span>
        </el-divider>
        <el-alert
          v-if="currentDetail.suggestion"
          type="success"
          :closable="false"
          show-icon
        >
          <template #title>
            <span style="white-space: pre-wrap; line-height: 1.8">{{ currentDetail.suggestion }}</span>
          </template>
        </el-alert>
        <p v-else style="color: #909399; padding: 10px">暂无修复建议，请参考官方文档或联系安全专家。</p>

        <!-- 可能后果 -->
        <el-divider content-position="left">
          <span style="color: #e6a23c; font-weight: bold">⚠️ 可能后果</span>
        </el-divider>
        <el-alert
          v-if="currentDetail.consequence"
          type="warning"
          :closable="false"
          show-icon
        >
          <template #title>
            <span style="white-space: pre-wrap; line-height: 1.8">{{ currentDetail.consequence }}</span>
          </template>
        </el-alert>
        <p v-else style="color: #909399; padding: 10px">暂无风险说明。</p>
      </div>
      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
        <el-button type="success" @click="confirmFinding(currentDetail.id)" :disabled="currentDetail.status !== 'open'">确认发现</el-button>
        <el-button type="warning" @click="markFalsePositive(currentDetail.id)" :disabled="currentDetail.status === 'false_positive'">标记误报</el-button>
      </template>
    </el-dialog>

    <!-- 报告弹窗 -->
    <el-dialog v-model="reportVisible" title="安全发现报告" width="600px">
      <div v-if="reportData">
        <el-row :gutter="20" style="margin-bottom: 20px">
          <el-col :span="6">
            <el-statistic title="总发现数" :value="reportData.total" />
          </el-col>
          <el-col :span="6">
            <el-statistic title="严重" :value="reportData.by_severity?.critical || 0" />
          </el-col>
          <el-col :span="6">
            <el-statistic title="高危" :value="reportData.by_severity?.high || 0" />
          </el-col>
          <el-col :span="6">
            <el-statistic title="中危" :value="reportData.by_severity?.medium || 0" />
          </el-col>
        </el-row>
        <el-divider>按扫描器分布</el-divider>
        <div v-for="(count, scanner) in reportData.by_scanner" :key="scanner" style="margin: 8px 0">
          <span style="display: inline-block; width: 120px">{{ scannerLabel(String(scanner)) }}</span>
          <el-progress :percentage="reportData.total > 0 ? Math.round(count / reportData.total * 100) : 0" :stroke-width="14" style="display: inline-block; width: 300px">
            <span>{{ count }}</span>
          </el-progress>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Loading, Search } from '@element-plus/icons-vue'
import axios from 'axios'
import dayjs from 'dayjs'

const findings = ref<any[]>([])
const findingStats = ref<Record<string, number>>({})
const loading = ref(false)
const scanning = ref('')
const scanResult = ref<any>(null)
const filterScanner = ref('')
const filterSeverity = ref('')
const searchQuery = ref('')
const detailVisible = ref(false)
const currentDetail = ref<any>(null)
const reportVisible = ref(false)
const reportData = ref<any>(null)
const currentPage = ref(1)
const pageSize = ref(10)
const fixingId = ref('')
const sortBySeverity = ref(true)
let refreshTimer: ReturnType<typeof setInterval> | null = null

const severityOrder: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1
}

const filteredFindings = computed(() => {
  let result = findings.value
  if (filterScanner.value) {
    result = result.filter((f: any) => f.scanner === filterScanner.value)
  }
  if (filterSeverity.value) {
    result = result.filter((f: any) => f.severity === filterSeverity.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter((f: any) =>
      f.title?.toLowerCase().includes(q) ||
      f.target?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q) ||
      f.scanner?.toLowerCase().includes(q)
    )
  }
  if (sortBySeverity.value) {
    result = [...result].sort((a: any, b: any) => {
      const diff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0)
      if (diff !== 0) return diff
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })
  }
  return result
})
const total = computed(() => filteredFindings.value.length)

const pagedFindings = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredFindings.value.slice(start, start + pageSize.value)
})

const statsByScanner = computed(() => {
  // 优先使用 API 返回的统计数据
  if (Object.keys(findingStats.value).length > 0) {
    return findingStats.value
  }
  // 降级：从前端数据计算
  const stats: Record<string, number> = {}
  for (const f of findings.value) {
    if (f.status !== 'false_positive') {
      stats[f.scanner] = (stats[f.scanner] || 0) + 1
    }
  }
  return stats
})

const severityType = (severity: string) => {
  const map: Record<string, string> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' }
  return map[severity] || 'info'
}
const severityLabel = (severity: string) => {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return map[severity] || severity
}
const statusType = (status: string) => {
  const map: Record<string, string> = { open: 'danger', confirmed: 'warning', fixed: 'success', resolved: 'success', false_positive: 'info', auto_resolved: 'info' }
  return map[status] || 'info'
}
const statusLabel = (status: string) => {
  const map: Record<string, string> = { open: '待处理', confirmed: '已确认', fixed: '已修复', resolved: '已修复', false_positive: '误报', auto_resolved: '已消失' }
  return map[status] || status
}
const scannerLabel = (scanner: string) => {
  const map: Record<string, string> = {
    serversecurity: '服务器安全',
    vulnscan: '漏洞扫描',
    websecurity: '网站安全',
    attackwarn: '攻击预警',
  }
  return map[scanner] || scanner
}
const scannerTagType = (scanner: string) => {
  const map: Record<string, string> = {
    serversecurity: 'primary',
    vulnscan: 'warning',
    websecurity: 'danger',
    attackwarn: 'success',
  }
  return map[scanner] || 'info'
}
const formatTime = (ts: string) => ts ? dayjs(ts).format('YYYY-MM-DD HH:mm:ss') : '-'

// 判断是否为外部威胁情报补充的漏洞（findings 的 detail 含 source=intel）
const isIntelFinding = (row: any) => {
  return typeof row?.detail === 'string' && row.detail.includes('"source":"intel"')
}

// 攻击类型中文映射（用于发现项标题翻译）
const attackTypeLabels: Record<string, string> = {
  'sql_injection': 'SQL注入攻击',
  'xss': 'XSS跨站脚本攻击',
  'cc_attack': 'CC攻击',
  'webshell_upload': 'Webshell上传攻击',
  'dir_traversal': '目录遍历攻击',
  'directory_traversal': '目录遍历攻击',
  'directory_brute': '目录爆破',
  'ssh_brute_force': 'SSH暴力破解',
  'port_scan': '端口扫描',
  'ddos_suspected': '疑似DDoS攻击',
  'ddos': 'DDoS攻击',
  'data_exfiltration': '数据外泄',
  'malicious_crawler': '恶意爬虫',
  'rate_limit_violation': '频率超限',
  'ban_limit_reached': '封禁上限',
}

// 格式化发现项标题：将英文攻击类型翻译为中文
const formatFindingTitle = (title: string) => {
  if (!title) return '-'
  let result = title
  for (const [eng, chn] of Object.entries(attackTypeLabels)) {
    result = result.split(eng).join(chn)
  }
  return result
}

const onFilterChange = () => {
  currentPage.value = 1
  loadFindings()
}

// 判断是否可自动修复
const canAutoFix = (row: any) => {
  if (!row.title) return false
  const title = row.title
  // nginx 安全头缺失
  if (title.includes('安全头缺失')) return true
  // 攻击预警类（SSH暴破、端口扫描等）
  if (row.scanner === 'attackwarn') return true
  // 目录权限过宽
  if (title.includes('权限') && title.includes('过宽')) return true
  // 敏感文件暴露
  if (title.includes('敏感文件') || title.includes('敏感信息暴露')) return true
  // SSH 配置安全问题
  if (title.includes('SSH') && title.includes('配置')) return true
  return false
}

const autoFix = async (id: string) => {
  fixingId.value = id
  try {
    const resp = await axios.post(`/api/findings/${id}/fix`)
    if (resp.data.fixed) {
      ElMessage.success(resp.data.detail || resp.data.message || '修复成功')
      loadFindings()
    } else if (resp.data.manual) {
      ElMessage.warning(resp.data.message || '该发现项需手动处理')
    } else {
      ElMessage.warning(resp.data.error || '暂不支持自动修复')
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '修复失败')
  } finally {
    fixingId.value = ''
  }
}

const loadFindings = async () => {
  loading.value = true
  try {
    // 始终加载全部发现项，前端筛选
    const resp = await axios.get('/api/findings', { params: { limit: 0 } })
    findings.value = resp.data.findings || []
    // 同时加载统计计数（独立于表格筛选）
    loadStats()
  } catch (e) {
    // 静默失败
  } finally {
    loading.value = false
  }
}

const loadStats = async () => {
  try {
    const resp = await axios.get('/api/findings/stats')
    findingStats.value = resp.data.counts || {}
  } catch {
    // 静默失败，降级为前端计算
  }
}

const triggerScan = async (type: string) => {
  scanning.value = type
  scanResult.value = null
  try {
    let resp: any
    if (type === 'websecurity') {
      resp = await axios.post('/api/scan/websecurity', { path: '/var/www' })
    } else if (type === 'vulnscan') {
      resp = await axios.post('/api/scan/vulnscan', { web_roots: ['/var/www', '/www/wwwroot'] })
    } else if (type === 'serversecurity') {
      resp = await axios.post('/api/scan/serversecurity', {})
    } else if (type === 'attackwarn') {
      resp = await axios.post('/api/scan/attackwarn', {})
    }
    scanResult.value = { message: resp.data.message || '扫描完成', type: 'success' }
    loadFindings()
  } catch (e: any) {
    scanResult.value = { message: e?.response?.data?.error || '扫描失败', type: 'error' }
  } finally {
    scanning.value = ''
  }
}

const showDetail = (row: any) => {
  currentDetail.value = row
  detailVisible.value = true
}

const confirmFinding = async (id: string) => {
  try {
    await axios.post(`/api/findings/${id}/confirm`)
    ElMessage.success('已确认')
    loadFindings()
  } catch (e) {
    ElMessage.error('操作失败')
  }
}

const markFalsePositive = async (id: string) => {
  try {
    await axios.post(`/api/findings/${id}/false-positive`)
    ElMessage.success('已标记为误报')
    loadFindings()
  } catch (e) {
    ElMessage.error('操作失败')
  }
}

const generateReport = async () => {
  try {
    const resp = await axios.post('/api/findings/report', null, {
      params: { scanner: filterScanner.value, severity: filterSeverity.value }
    })
    reportData.value = resp.data
    reportVisible.value = true
  } catch (e) {
    ElMessage.error('生成报告失败')
  }
}

onMounted(() => {
  loadFindings()
  // 每 30 秒自动刷新，展示 Agent 自动扫描的最新结果
  refreshTimer = setInterval(loadFindings, 30000)
})

onUnmounted(() => {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null }
})
</script>

<style scoped>
.findings-page { width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 10px; align-items: center; }
.scan-buttons { display: flex; gap: 15px; flex-wrap: wrap; }

.stat-card { cursor: default; }
.stat-content { display: flex; align-items: center; gap: 12px; }
.stat-icon { font-size: 28px; line-height: 1; }
.stat-body { flex: 1; }
.stat-value { font-size: 28px; font-weight: bold; line-height: 1.2; }
.stat-label { font-size: 13px; color: #909399; margin-top: 4px; }
.stat-server .stat-value { color: #409eff; }
.stat-vuln .stat-value { color: #e6a23c; }
.stat-web .stat-value { color: #f56c6c; }
.stat-attack .stat-value { color: #67c23a; }
</style>
