<template>
  <div class="incidents-page">
    <div class="page-header">
      <div class="header-left">
        <h2>故障事件</h2>
        <span class="header-sub">根因链推理 · 多条告警关联为一条因果链</span>
      </div>
      <el-button-group>
        <el-radio-group v-model="statusFilter" @change="fetchData" size="small">
          <el-radio-button value="">全部</el-radio-button>
          <el-radio-button value="open">进行中</el-radio-button>
          <el-radio-button value="resolved">已解决</el-radio-button>
        </el-radio-group>
        <el-button :icon="Refresh" @click="fetchData" :loading="loading">刷新</el-button>
      </el-button-group>
    </div>

    <!-- 事件列表 -->
    <el-table :data="pagedIncidents" v-loading="loading" stripe @row-click="showDetail" style="cursor: pointer">
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-tag :type="row.status === 'open' ? 'danger' : 'success'" size="small" effect="dark">
            {{ row.status === 'open' ? '进行中' : '已解决' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="根因" min-width="200" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="root-title">{{ row.root_title }}</span>
        </template>
      </el-table-column>
      <el-table-column label="来源" width="100">
<template #default="{ row }">{{ sourceLabel(row.root_source) }}</template>
</el-table-column>
      <el-table-column label="关联告警" width="90" align="center">
        <template #default="{ row }">
          <el-badge :value="row.member_alerts?.length || 0" type="primary" />
        </template>
      </el-table-column>
      <el-table-column label="因果链" width="80" align="center">
        <template #default="{ row }">
          <el-tag v-if="row.chain?.length > 0" size="small" type="warning">{{ row.chain.length }} 条</el-tag>
          <span v-else class="text-muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="处置动作" width="90" align="center">
        <template #default="{ row }">
          <el-badge v-if="row.actions?.length > 0" :value="row.actions.length" type="success" />
          <span v-else class="text-muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="发生时间" width="150">
        <template #default="{ row }">
          {{ formatTime(row.root_time) }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="100" fixed="right">
        <template #default="{ row }">
          <el-button v-if="row.status === 'open'" size="small" type="primary" @click.stop="ackIncident(row)">
            确认
          </el-button>
          <el-button size="small" text @click.stop="showDetail(row)">详情</el-button>
        </template>
      </el-table-column>
</el-table>
<div style="margin-top: 16px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize" :page-sizes="[10, 20, 50, 100]" :total="incidents.length" layout="total, sizes, prev, pager, next" />
</div>
    <el-drawer v-model="detailVisible" size="600px" :title="`故障事件详情`">
      <template v-if="currentIncident">
        <!-- 根因区 -->
        <el-descriptions :column="1" border>
          <el-descriptions-item label="事件 ID">{{ currentIncident.id }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="currentIncident.status === 'open' ? 'danger' : 'success'" size="small">
              {{ currentIncident.status === 'open' ? '进行中' : '已解决' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="根因">{{ currentIncident.root_title }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ sourceLabel(currentIncident.root_source) }}</el-descriptions-item>
          <el-descriptions-item label="发生时间">{{ formatTime(currentIncident.root_time) }}</el-descriptions-item>
          <el-descriptions-item v-if="currentIncident.ended_at" label="结束时间">{{ formatTime(currentIncident.ended_at) }}</el-descriptions-item>
        </el-descriptions>

        <!-- 摘要 -->
        <div v-if="currentIncident.summary" class="detail-section">
          <h4>📋 事件摘要</h4>
          <div class="summary-box">{{ currentIncident.summary }}</div>
        </div>

        <!-- 因果链 -->
        <div v-if="currentIncident.chain?.length > 0" class="detail-section">
          <h4>🔗 因果链</h4>
          <div class="chain-container">
            <div v-for="(link, i) in currentIncident.chain" :key="i" class="chain-item">
              <div class="chain-from">{{ link.from }}</div>
              <div class="chain-arrow">↓ <span class="chain-via">{{ formatVia(link.via) }}</span></div>
              <div class="chain-to">{{ link.to }}</div>
            </div>
          </div>
        </div>

        <!-- 关联告警 -->
        <div v-if="currentIncident.member_alerts?.length > 0" class="detail-section">
          <h4>⚠️ 关联告警（{{ currentIncident.member_alerts.length }} 条）</h4>
          <el-timeline>
            <el-timeline-item
              v-for="alert in currentIncident.member_alerts"
              :key="alert.alert_id"
              :timestamp="formatTime(alert.time)"
              :type="alertLevelType(alert.level)"
            >
              <div class="alert-item">
                <el-tag :type="alertLevelType(alert.level)" size="small">{{ alertLevelText(alert.level) }}</el-tag>
                <span class="alert-title">{{ alert.title }}</span>
                <span class="alert-source">{{ sourceLabel(alert.source) }}</span>
              </div>
            </el-timeline-item>
          </el-timeline>
        </div>

        <!-- 处置动作 -->
        <div v-if="currentIncident.actions?.length > 0" class="detail-section">
          <h4>🔧 自动处置（{{ currentIncident.actions.length }} 项）</h4>
          <div v-for="(action, i) in currentIncident.actions" :key="i" class="action-item">
            {{ action }}
          </div>
        </div>

        <!-- LLM 解释 -->
        <div class="detail-section">
          <el-button :loading="llmLoading" @click="fetchLLMExplanation" type="primary" plain>
            🤖 AI 解释此事件
          </el-button>
          <div v-if="llmExplanation" class="llm-explanation-box">{{ llmExplanation }}</div>
        </div>
      </template>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import axios from 'axios'
import dayjs from 'dayjs'

const loading = ref(false)
const incidents = ref<any[]>([])
const statusFilter = ref('')
const detailVisible = ref(false)
const currentIncident = ref<any>(null)
const llmLoading = ref(false)
const llmExplanation = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const pagedIncidents = computed(() => {
const start = (currentPage.value - 1) * pageSize.value
return incidents.value.slice(start, start + pageSize.value)
})

function formatTime(ts: string): string {
  if (!ts) return '—'
  return dayjs(ts).format('MM-DD HH:mm:ss')
}

function formatVia(via: string): string {
  if (!via) return ''
  if (via.startsWith('domain-rule:')) return via.substring(12)
  if (via === 'same-source') return '同源连锁'
  return via
}

function alertLevelType(level: string): string {
  if (level === 'critical' || level === 'fatal') return 'danger'
  if (level === 'error') return 'danger'
  if (level === 'warning') return 'warning'
  return 'info'
}

function alertLevelText(level: string): string {
  const labels: Record<string, string> = {
    critical: '严重', fatal: '致命', error: '错误', warning: '警告', info: '提醒',
  }
  return labels[level] || level || '—'
}

const sourceLabels: Record<string, string> = {
  vulnscan: '漏洞扫描', serversecurity: '服务器安全', websecurity: '网站安全',
  attackwarn: '攻击预警', resource: '资源守护', service: '服务守护',
  security: '安全防护', log: '日志防护', network: '网络守护', system: '系统守护',
  cert: '证书守护', docker: '容器守护', config: '配置守护', database: '数据库守护',
  storage: '存储管理', baota: '宝塔面板', agent: 'Agent', baseline: '基线检测',
  forecast: '趋势预测', correlation: '故障关联', traffic: '流量守护',
  ai: 'AI 异常检测', tuning: '调优顾问', devops: 'DevOps', datagovern: '数据治理',
  hub: '中心管理', apm: 'APM 分析', netquality: '网络质量', anomaly: '异常检测',
  healthscore: '健康评分', knowledge: '知识库', probe: '站点探测', heartbeat: '心跳',
  posture: '系统态势', notifier: '通知系统', upgrade: '版本升级',
  nginx: 'Nginx', redis: 'Redis', mysql: 'MySQL', slowquery: '慢查询',
  backup: '备份守护', fd: '文件描述符', dns: 'DNS', clock: '时钟同步',
}
function sourceLabel(src?: string): string {
  if (!src) return '—'
  return sourceLabels[src] || src
}

async function fetchData() {
  loading.value = true
  try {
    const resp = await axios.get('/api/incidents', {
      params: { status: statusFilter.value, limit: 50 }
    })
    incidents.value = resp.data.incidents || []
  } catch {
    incidents.value = []
  } finally {
    loading.value = false
  }
}

async function showDetail(row: any) {
  currentIncident.value = row
  llmExplanation.value = ''
  detailVisible.value = true
}

async function ackIncident(row: any) {
  try {
    await axios.post(`/api/incidents/${row.id}/ack`)
    row.status = 'resolved'
  } catch {
    // ignore
  }
}

async function fetchLLMExplanation() {
  if (!currentIncident.value) return
  llmLoading.value = true
  llmExplanation.value = ''
  const incidentId = currentIncident.value.id
  try {
    const resp = await axios.get(`/api/llm/explain-incident/${incidentId}`)
    if (resp.data.status === 'running') {
      // 后端异步调用 LLM（最长约 30s），轮询等待结果，而不是把"进行中"误显示为失败
      for (let i = 0; i < 15; i++) {
        await new Promise(r => setTimeout(r, 2000))
        // 对话框关闭或切换了事件则停止轮询
        if (!detailVisible.value || currentIncident.value?.id !== incidentId) { llmLoading.value = false; return }
        const r2 = await axios.get(`/api/llm/explain-incident/${incidentId}`)
        if (r2.data.status !== 'running') {
          llmExplanation.value = r2.data.explanation || '无法生成解释'
          llmLoading.value = false
          return
        }
      }
      llmExplanation.value = 'AI 解释生成超时，请稍后重新点击'
    } else {
      llmExplanation.value = resp.data.explanation || '无法生成解释'
    }
  } catch (err: any) {
    llmExplanation.value = err?.response?.data?.error || '请求失败'
  } finally {
    llmLoading.value = false
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.incidents-page { padding: 20px; }
.page-header {
  display: flex; justify-content: space-between; align-items: flex-start;
  margin-bottom: 20px;
}
.header-left h2 { margin: 0; font-size: 20px; }
.header-sub { font-size: 13px; color: #909399; }
.root-title { font-weight: 600; }
.text-muted { color: #c0c4cc; }

.detail-section { margin-top: 24px; }
.detail-section h4 { margin-bottom: 12px; font-size: 15px; }

.summary-box {
  background: #f5f7fa; border-radius: 8px; padding: 16px;
  white-space: pre-wrap; line-height: 1.8; font-size: 14px; color: #606266;
}

.chain-container { display: flex; flex-direction: column; gap: 8px; }
.chain-item { display: flex; flex-direction: column; align-items: center; }
.chain-from, .chain-to {
  background: #fff; border: 1px solid #e4e7ed; border-radius: 8px;
  padding: 8px 16px; font-size: 14px; font-weight: 500;
}
.chain-to { border-color: #f56c6c; color: #f56c6c; }
.chain-arrow { color: #909399; font-size: 12px; padding: 4px 0; }
.chain-via { font-style: italic; color: #e6a23c; }

.alert-item { display: flex; align-items: center; gap: 8px; }
.alert-title { font-weight: 500; }
.alert-source { color: #909399; font-size: 12px; }

.action-item {
  background: #f0f9ff; border-left: 3px solid #409eff; padding: 8px 12px;
  margin-bottom: 8px; font-size: 13px; color: #606266; border-radius: 4px;
}

.llm-explanation-box {
  margin-top: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff; border-radius: 8px; padding: 16px; white-space: pre-wrap;
  line-height: 1.8; font-size: 14px;
}
</style>
