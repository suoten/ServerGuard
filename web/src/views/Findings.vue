<template>
  <div class="findings-page">
    <!-- 自动扫描状态提示 -->
    <el-card style="margin-bottom: 20px">
      <template #header>
        <div class="card-header">
          <span>自动安全扫描</span>
          <el-tag type="success" size="small">自动轮转扫描 · 约 40 分钟一轮</el-tag>
        </div>
      </template>
<el-alert type="info" :closable="false" show-icon>
Agent 按轮转计划自动执行四项安全扫描（服务器安全、漏洞扫描、网站安全、攻击预警），下方列表展示自动发现的结果。
如需立即触发扫描，可点击右侧按钮。
</el-alert>
      <div class="scan-buttons" style="margin-top: 15px">
        <el-button type="primary" size="small" @click="triggerScan('serversecurity')" :loading="scanning==='serversecurity' || scanStatus.serversecurity?.running">
          立即扫描·服务器安全
        </el-button>
        <el-button type="warning" size="small" @click="triggerScan('vulnscan')" :loading="scanning==='vulnscan' || scanStatus.vulnscan?.running">
          立即扫描·漏洞
        </el-button>
        <el-button type="danger" size="small" @click="triggerScan('websecurity')" :loading="scanning==='websecurity' || scanStatus.websecurity?.running">
          立即扫描·网站安全
        </el-button>
        <el-button type="info" size="small" plain @click="diagnoseWebSecurity" :loading="diagnosing">
          诊断·站点发现
        </el-button>
        <el-button type="success" size="small" @click="triggerScan('attackwarn')" :loading="scanning==='attackwarn' || scanStatus.attackwarn?.running">
          立即扫描·攻击预警
        </el-button>
      </div>
      <!-- 各扫描器状态 -->
      <div class="scan-status-grid" style="margin-top: 12px; display: flex; gap: 16px; flex-wrap: wrap;">
        <div v-for="s in ['serversecurity','vulnscan','websecurity','attackwarn']" :key="s" class="scan-status-item" style="font-size: 12px; color: #909399;">
          <span>{{ scanNames[s] }}:</span>
          <el-tag v-if="scanStatus[s]?.running" type="warning" size="small">扫描中...</el-tag>
          <span v-else-if="scanStatus[s]?.last_time">
            上次: {{ scanStatus[s].last_time }}
            <el-tag v-if="scanStatus[s]?.last_count > 0" type="danger" size="small">{{ scanStatus[s].last_count }} 项</el-tag>
            <el-tag v-else type="success" size="small">无风险</el-tag>
          </span>
          <span v-else>尚未扫描</span>
        </div>
      </div>
      <el-alert v-if="scanResult" :title="scanResult.message" :type="scanResult.type" show-icon closable @close="scanResult = null" style="margin-top: 15px" />
<!-- 诊断结果 -->
<el-dialog v-model="diagnoseVisible" title="网站安全扫描诊断" width="700px">
  <pre class="diagnose-output">{{ diagnoseResult }}</pre>
  <template #footer>
    <el-button type="primary" @click="diagnoseScan" :loading="diagnoseScanning" :disabled="diagnoseNoTargets">试扫第一个站点</el-button>
    <el-button @click="diagnoseVisible = false">关闭</el-button>
  </template>
</el-dialog>
<!-- 误报自动清理（无需手动操作，页面加载时自动执行） -->
    </el-card>

    <!-- 严重度筛选卡片 -->
    <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap">
      <div
        v-for="tab in severityTabs"
        :key="tab.key"
        @click="filterSeverity = tab.key; onFilterChange()"
        :style="{
          cursor: 'pointer',
          flex: '1 1 100px',
          minWidth: '100px',
          padding: '10px 14px',
          borderRadius: '8px',
          border: filterSeverity === tab.key ? `2px solid ${tab.color}` : '1px solid #e4e7ed',
          background: filterSeverity === tab.key ? tab.bg : '#fff',
          transition: 'all 0.2s',
          textAlign: 'center',
        }"
      >
        <div :style="{ fontSize: '22px', fontWeight: 700, color: tab.color, lineHeight: '1.2' }">
          {{ tab.count }}
        </div>
        <div style="font-size: 12px; color: #909399; margin-top: 4px">{{ tab.label }}</div>
      </div>
    </div>

    <!-- 统计卡片（可点击筛选） -->
    <el-row :gutter="16" style="margin-bottom: 20px">
      <el-col :span="6" v-for="card in scannerCards" :key="card.key">
        <el-card
          shadow="hover"
          :class="['stat-card', card.class, { 'stat-card-active': filterScanner === card.key }]"
          @click="filterScanner = filterScanner === card.key ? '' : card.key; onFilterChange()"
          :style="{ cursor: 'pointer', border: filterScanner === card.key ? '2px solid ' + card.borderColor : undefined }"
        >
          <div class="stat-content">
            <div class="stat-icon">{{ card.icon }}</div>
            <div class="stat-body">
              <div class="stat-value"><CountUp :value="card.count" /></div>
              <div class="stat-label">{{ card.label }}</div>
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
            <el-icon v-if="anyScanRunning" style="font-size: 32px; color: #409eff; margin-bottom: 10px" class="is-loading"><Loading /></el-icon>
            <el-icon v-else style="font-size: 32px; color: #c0c4cc; margin-bottom: 10px"><Search /></el-icon>
            <template v-if="anyScanRunning">
              <p style="color: #409eff; margin: 0">Agent 正在执行安全扫描，请稍候...</p>
              <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">扫描完成后将自动显示结果</p>
            </template>
            <template v-else>
              <p style="color: #909399; margin: 0">暂无安全发现项</p>
              <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">Agent 会自动执行定期扫描，也可点击上方按钮手动触发</p>
            </template>
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
            <div style="text-align: center">
              <div style="font-size: 28px; font-weight: bold; color: #409eff"><CountUp :value="reportData.total" /></div>
              <div style="font-size: 12px; color: #909399; margin-top: 4px">总发现数</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div style="text-align: center">
              <div style="font-size: 28px; font-weight: bold; color: #f56c6c"><CountUp :value="reportData.by_severity?.critical || 0" /></div>
              <div style="font-size: 12px; color: #909399; margin-top: 4px">严重</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div style="text-align: center">
              <div style="font-size: 28px; font-weight: bold; color: #e6a23c"><CountUp :value="reportData.by_severity?.high || 0" /></div>
              <div style="font-size: 12px; color: #909399; margin-top: 4px">高危</div>
            </div>
          </el-col>
          <el-col :span="6">
            <div style="text-align: center">
              <div style="font-size: 28px; font-weight: bold; color: #67c23a"><CountUp :value="reportData.by_severity?.medium || 0" /></div>
              <div style="font-size: 12px; color: #909399; margin-top: 4px">中危</div>
            </div>
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
import CountUp from '../components/CountUp.vue'

const findings = ref<any[]>([])
const findingStats = ref<Record<string, number>>({})
const loading = ref(false)
const scanning = ref('')
const diagnosing = ref(false)
const diagnoseVisible = ref(false)
const diagnoseResult = ref('')
const diagnoseScanning = ref(false)
const diagnoseNoTargets = ref(false)
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

// 扫描状态跟踪
const scanStatus = ref<Record<string, any>>({})
const scanNames: Record<string, string> = {
  serversecurity: '服务器安全',
  vulnscan: '漏洞扫描',
  websecurity: '网站安全',
  attackwarn: '攻击预警'
}
const anyScanRunning = computed(() =>
Object.values(scanStatus.value).some((s: any) => s?.running)
)

const severityOrder: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1
}

const filteredFindings = computed(() => {
  // 统一排除误报和已消失的发现项，与统计卡片口径一致
  let result = findings.value.filter((f: any) => f.status !== 'false_positive' && f.status !== 'auto_resolved')
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
  // 优先使用 API 返回的统计数据（后端已排除 false_positive 和 auto_resolved）
  if (Object.keys(findingStats.value).length > 0) {
    return findingStats.value
  }
  // 降级：从前端数据计算（排除误报和已消失）
  const stats: Record<string, number> = {}
  for (const f of findings.value) {
    if (f.status !== 'false_positive' && f.status !== 'auto_resolved') {
      stats[f.scanner] = (stats[f.scanner] || 0) + 1
    }
  }
  return stats
})

const severityStatsFindings = computed(() => {
  const stats: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings.value) {
    if (f.status !== 'false_positive' && f.status !== 'auto_resolved' && stats[f.severity] !== undefined) {
      stats[f.severity]++
    }
  }
  return stats
})

const severityTabs = computed(() => [
  { key: '', label: '全部', count: findings.value.filter((f: any) => f.status !== 'false_positive' && f.status !== 'auto_resolved').length, color: '#409eff', bg: '#ecf5ff' },
  { key: 'critical', label: '严重', count: severityStatsFindings.value.critical, color: '#f56c6c', bg: '#fef0f0' },
  { key: 'high', label: '高危', count: severityStatsFindings.value.high, color: '#f56c6c', bg: '#fef0f0' },
  { key: 'medium', label: '中危', count: severityStatsFindings.value.medium, color: '#e6a23c', bg: '#fdf6ec' },
  { key: 'low', label: '低危', count: severityStatsFindings.value.low, color: '#909399', bg: '#f4f4f5' },
  { key: 'info', label: '信息', count: severityStatsFindings.value.info, color: '#909399', bg: '#f4f4f5' },
])

const scannerCards = computed(() => [
  { key: 'serversecurity', label: '服务器安全', icon: '🛡️', class: 'stat-server', borderColor: '#409eff', count: statsByScanner.value.serversecurity || 0 },
  { key: 'vulnscan', label: '漏洞扫描', icon: '🐛', class: 'stat-vuln', borderColor: '#e6a23c', count: statsByScanner.value.vulnscan || 0 },
  { key: 'websecurity', label: '网站安全', icon: '🌐', class: 'stat-web', borderColor: '#f56c6c', count: statsByScanner.value.websecurity || 0 },
  { key: 'attackwarn', label: '攻击预警', icon: '⚠️', class: 'stat-attack', borderColor: '#67c23a', count: statsByScanner.value.attackwarn || 0 },
])

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
  'dir_bruteforce': '目录爆破探测',
  'ssh_brute_force': 'SSH暴力破解',
  'port_scan': '端口扫描',
  'ddos_suspected': '疑似DDoS攻击',
  'ddos': 'DDoS攻击',
  'web_scanner': 'Web扫描器探测',
  'sensitive_probe': '敏感文件探测',
  'code_injection': '远程代码执行攻击',
  'cms_bruteforce': '后台登录爆破',
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

const loadScanStatus = async () => {
  try {
    const resp = await axios.get('/api/scan/status')
    scanStatus.value = resp.data || {}
  } catch {
    // 静默失败
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

let scanPollTimer: ReturnType<typeof setTimeout> | null = null

// 诊断网站安全扫描（快速模式：只看站点发现，不执行扫描）
const diagnoseWebSecurity = async () => {
  diagnosing.value = true
  diagnoseNoTargets.value = false
  try {
    const resp = await axios.get('/api/scan/websecurity/diagnose')
    const d = resp.data
    const lines: string[] = []
    lines.push(`OS: ${d.os}`)
    lines.push(`宝塔环境: ${d.baota?.detected ? '是' : '否'} (WebRoot: ${d.baota?.web_root || 'N/A'})`)
    lines.push(`站点发现: ${d.site_discovery_count} 个站点配置`)
    lines.push(`有效扫描目标: ${d.target_count} 个`)
    lines.push('')
    if (d.target_count === 0) {
      lines.push('⚠️ 未发现任何站点！可能原因：')
      lines.push('  - 站点在数据盘上，常见路径未覆盖')
      lines.push('  - 宝塔配置文件未正确解析')
      lines.push('  - Nginx/Apache 配置不在默认位置')
      diagnoseNoTargets.value = true
    } else {
      lines.push('扫描目标列表:')
      for (const t of (d.targets || []).slice(0, 30)) {
        lines.push(`  ${t.path} (Host: ${t.host})`)
      }
      if ((d.targets || []).length > 30) {
        lines.push(`  ... 共 ${d.targets.length} 个`)
      }
    }
    lines.push('')
    lines.push(`子扫描器 (${(d.sub_scanners || []).length} 个):`)
    for (const s of (d.sub_scanners || [])) {
      lines.push(`  ${s.sub} - ${s.name}`)
    }
    lines.push('')
    lines.push('提示: 点击「试扫第一个站点」执行实际扫描，查看各子扫描器结果')
    diagnoseResult.value = lines.join('\n')
    diagnoseVisible.value = true
  } catch (e: any) {
    const status = e?.response?.status
    const errData = e?.response?.data
    const errMsg = (typeof errData === 'string') ? errData : (errData?.error || errData?.message || '')
    const lines: string[] = []
    lines.push('诊断失败')
    lines.push(`HTTP 状态码: ${status || 'N/A（可能网络超时或服务未运行）'}`)
    if (errMsg) lines.push(`错误信息: ${errMsg}`)
    if (e?.message && !errMsg) lines.push(`异常: ${e.message}`)
    lines.push('')
    lines.push('可能原因:')
    lines.push('1. 服务端版本太旧，不支持诊断接口 → 请更新到最新版本')
    lines.push('2. 服务未运行或网络不通 → 检查服务状态和端口')
    lines.push('3. Nginx 反代超时 → 检查 nginx proxy_read_timeout 设置')
    diagnoseResult.value = lines.join('\n')
    diagnoseVisible.value = true
  } finally {
    diagnosing.value = false
  }
}

// 诊断试扫：对第一个站点执行各子扫描器，返回结果数
const diagnoseScan = async () => {
  diagnoseScanning.value = true
  try {
    // 追加扫描结果到现有诊断输出
    const resp = await axios.get('/api/scan/websecurity/diagnose?scan=1', { timeout: 120000 })
    const d = resp.data
    const lines: string[] = []
    lines.push('═══════════════════════════════════════════')
    lines.push('子扫描器结果（第一个站点）:')
    lines.push('═══════════════════════════════════════════')
    const results = d.sub_scanner_results || []
    if (results.length === 0) {
      lines.push('（无扫描结果）')
    }
    let totalFindings = 0
    for (const s of results) {
      totalFindings += (s.findings || 0)
      lines.push(`  ${s.sub}: ${s.findings} 项${s.error ? ' ⚠️错误: ' + s.error : ''}`)
      if (s.sample && s.sample.length > 0) {
        for (const sm of s.sample) {
          lines.push(`    → [${sm.severity}] ${sm.title} (${sm.target})`)
        }
      }
    }
    lines.push('')
    lines.push(`合计: ${totalFindings} 项发现`)
    diagnoseResult.value = diagnoseResult.value + '\n\n' + lines.join('\n')
  } catch (e: any) {
    const status = e?.response?.status
    const errData = e?.response?.data
    const errMsg = (typeof errData === 'string') ? errData : (errData?.error || errData?.message || '')
    const lines: string[] = []
    lines.push('')
    lines.push('试扫失败:')
    lines.push(`HTTP 状态码: ${status || 'N/A'}`)
    if (errMsg) lines.push(`错误信息: ${errMsg}`)
    if (e?.message && !errMsg) lines.push(`异常: ${e.message}`)
    lines.push('')
    lines.push('如果是 502/504: Nginx 反代超时，需要增加 proxy_read_timeout')
    diagnoseResult.value = diagnoseResult.value + '\n\n' + lines.join('\n')
  } finally {
    diagnoseScanning.value = false
  }
}

const triggerScan = async (type: string) => {
  scanning.value = type
  scanResult.value = null
  try {
    let resp: any
    if (type === 'websecurity') {
      // 不传 path，让后端自动发现网站根目录（宝塔 /www/wwwroot、常规 /var/www 等）
      resp = await axios.post('/api/scan/websecurity', {})
    } else if (type === 'vulnscan') {
      // 不传 web_roots，让后端自动发现网站根目录
      resp = await axios.post('/api/scan/vulnscan', {})
    } else if (type === 'serversecurity') {
      resp = await axios.post('/api/scan/serversecurity', {})
    } else if (type === 'attackwarn') {
      resp = await axios.post('/api/scan/attackwarn', {})
    }
    // 异步扫描：后端返回 202，扫描在后台执行
    scanResult.value = { message: resp.data.message || '扫描已启动，请稍后查看结果', type: 'success' }
    // 立即刷新一次（清空旧数据提示），然后启动轮询等待新结果
    loadFindings()
    loadScanStatus()
    // 3 秒后开始轮询，每 5 秒刷新一次，持续 5 分钟（部分扫描耗时较长）
    if (scanPollTimer) clearTimeout(scanPollTimer)
    let pollCount = 0
    const maxPolls = 60 // 5 分钟 / 5 秒 = 60 次
    const pollFindings = () => {
      if (pollCount >= maxPolls) return
      pollCount++
      loadFindings()
      loadScanStatus()
      scanPollTimer = setTimeout(pollFindings, 5000)
    }
    scanPollTimer = setTimeout(pollFindings, 3000)
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

// 已禁用规则产生的误报告警标题列表
const falsePositivePatterns = [
// ===== 网站安全 (websecurity) =====
'十六进制混淆', '短十六进制混淆', '长十六进制混淆',
'Unicode转义混淆', 'String.fromCharCode混淆',
'超长变量名混淆', 'Null Byte注入', 'str_replace长字符串混淆',
'goto混淆控制流', '变量函数调用型Webshell', '外部JS引用',
'SSL 弱协议启用',     // 修复了 TLSv1 子串匹配 bug（TLSv1.2 被误匹配），且跳过 .bak 备份文件
'脚本文件有执行权限', // 不再对 PHP/JSP/ASP 文件报告执行权限（仅 .sh/.py 等 shell 脚本）
'可疑文件名',        // 跳过框架缓存目录（runtime/temp/cache 等），只检测 8-16 位短哈希文件名
// 旧版通用正则收紧后产生的误报（已收紧正则，清理历史数据）
// "HTTP参数直接命令执行" 旧正则匹配了泛化的 req/param 关键词，框架中 exec($param) 被误判
// "Base64编码命令执行" 旧正则匹配了泛化的 base64 关键词，框架正常 base64 编码被误判
// "远程下载并执行" 旧正则匹配了泛化的 urllib/requests/http 关键词，框架 HTTP 客户端被误判
// 这些已收紧正则，但需要清理 vendor 目录下框架文件的旧误报
// 注意：不能直接加标题到清理列表，因为真正的 webshell 也可能用这些模式
// 通过后端的 vendor 框架文件排除逻辑来避免新的误报，旧的需要手动确认或标记误报
// YARA 规则误报（exploit.yar 中禁用了通用函数名匹配）
'YARA 规则匹配: exploit_bof_sprintf',  // sprintf 是 PHP 标准函数
'YARA 规则匹配: exploit_bof_strcpy',   // strcpy 是 C 标准函数
'YARA 规则匹配: exploit_bof_gets',     // gets 是 C 标准函数
'YARA 规则匹配: exploit_bof_strcat',   // strcat 是 C 标准函数
'YARA 规则匹配: exploit_xss_script_tag', // <script> 在正常 HTML 中
'YARA 规则匹配: exploit_xss_onerror',    // onerror 是正常 HTML 事件属性
'YARA 规则匹配: exploit_xss_onload',     // onload 是正常 HTML 事件属性
'YARA 规则匹配: exploit_xss_document_cookie', // document.cookie 在正常 JS 中
'YARA 规则匹配: exploit_path_traversal_dotdot', // ../ 在正常路径引用中
'YARA 规则匹配: exploit_ssrf_localhost',  // 127.0.0.1/localhost 在正常配置中
'YARA 规则匹配: exploit_rce_deserialize', // unserialize 在 PHP 中常用
'YARA 规则匹配: exploit_crlf_injection',  // \r\n 是正常换行
'YARA 规则匹配: exploit_open_redirect',    // redirect/location 在正常代码中
'YARA 规则匹配: exploit_shellcode_int80',  // \xcd\x80 只有 2 字节
'YARA 规则匹配: exploit_shellcode_syscall', // \x0f\x05 只有 2 字节
'YARA 规则匹配: exploit_heartbleed',       // \x18\x03 只有 2 字节
'YARA 规则匹配: exploit_ldap_injection',   // 模式太宽泛
// YARA 规则误报（malware.yar 中禁用了通用模式匹配）
'YARA 规则匹配: malware_xor_decode',       // for 循环中含 ^ 太常见
'YARA 规则匹配: malware_hidden_process',   // .数字/ 路径太常见
'YARA 规则匹配: malware_tmp_exec_binary',  // /tmp/.xxx 在正常代码中
'YARA 规则匹配: malware_rootkit_hide',     // hook/intercept 太通用
'YARA 规则匹配: malware_c2_beacon',        // beacon/heartbeat 太通用
'YARA 规则匹配: malware_ld_preload',       // LD_PRELOAD 在正常配置中
'最近创建的可疑脚本',  // 收紧检测：要求多个危险函数+用户输入才报告
'文件内容熵值异常',   // 提高阈值到 7.5，增大最小文件到 4KB
// ===== 漏洞扫描 (vulnscan) =====
'检测到 CMS:',          // 仅检测到 CMS 不再报告（只在旧版本有漏洞时报告）
'检测到依赖文件:',      // 不再为依赖文件生成发现
'内核参数不合规: net.ipv4.ip_forward', // Docker/K8s 环境需要 ip_forward=1
// ===== 服务器安全 (serversecurity) =====
'IP 转发已开启',        // Docker 环境不再误报，只在非 Docker 环境报告
// 注意：安全头缺失不在此列表，因为它对主配置文件仍然有效
]

// 计算已知误报数量
const falsePositiveCount = computed(() => {
return findings.value.filter((f: any) =>
f.status === 'open' &&
falsePositivePatterns.some(p => f.title?.includes(p))
).length
})

const batchCleaning = ref(false)

const batchCleanFalsePositives = async () => {
batchCleaning.value = true
try {
// 不指定 scanner，清除所有扫描器的误报
const resp = await axios.post('/api/findings/batch-resolve', {
scanner: '',
title_patterns: falsePositivePatterns,
})
ElMessage.success(resp.data.message || `成功清理 ${resp.data.resolved_count} 条误报告警`)
loadFindings()
loadStats()
} catch (e: any) {
ElMessage.error(e?.response?.data?.error || '清理失败')
} finally {
batchCleaning.value = false
}
}

// 自动清理已知误报（页面加载时静默执行，不需要用户手动操作）
const autoCleanFalsePositives = async () => {
try {
const resp = await axios.post('/api/findings/batch-resolve', {
scanner: '',
title_patterns: falsePositivePatterns,
})
if (resp.data?.resolved_count > 0) {
console.log(`自动清理了 ${resp.data.resolved_count} 条误报告警`)
loadFindings()
loadStats()
}
} catch {
// 静默失败
}
}

onMounted(() => {
loadFindings()
loadScanStatus()
// 自动清理已知误报（无需用户手动操作）
autoCleanFalsePositives()
// 每 30 秒自动刷新，展示 Agent 自动扫描的最新结果
refreshTimer = setInterval(() => {
loadFindings()
loadScanStatus()
}, 30000)
})

onUnmounted(() => {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null }
  if (scanPollTimer) { clearTimeout(scanPollTimer); scanPollTimer = null }
})
</script>

<style scoped>
.findings-page { width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 10px; align-items: center; }
.scan-buttons { display: flex; gap: 15px; flex-wrap: wrap; }

.stat-card { cursor: pointer; transition: all 0.2s; }
.stat-card:hover { transform: translateY(-2px); }
.stat-card-active { box-shadow: 0 0 0 2px var(--el-color-primary); }
.stat-content { display: flex; align-items: center; gap: 12px; }
.stat-icon { font-size: 28px; line-height: 1; }
.stat-body { flex: 1; }
.stat-value { font-size: 28px; font-weight: bold; line-height: 1.2; }
.stat-label { font-size: 13px; color: #909399; margin-top: 4px; }
.stat-server .stat-value { color: #409eff; }
.stat-vuln .stat-value { color: #e6a23c; }
.stat-web .stat-value { color: #f56c6c; }
.stat-attack .stat-value { color: #67c23a; }

.diagnose-output {
  margin: 0;
  padding: 16px;
  background: #1e293b;
  color: #e2e8f0;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 60vh;
  overflow-y: auto;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
</style>
