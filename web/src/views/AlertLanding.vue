<template>
  <div class="alert-landing">
    <!-- 骨架屏 -->
    <div v-if="loading" class="landing-skeleton">
      <div class="skeleton-circle" />
      <div class="skeleton-line" style="width: 60%" />
      <div class="skeleton-line" style="width: 40%" />
    </div>

    <!-- 错误状态 -->
    <div v-else-if="error" class="landing-error">
      <el-icon :size="48" color="#f56c6c"><WarningFilled /></el-icon>
      <p class="error-title">无法获取告警信息</p>
      <p class="error-desc">{{ error }}</p>
      <el-button type="primary" size="large" @click="fetchAlert">重试</el-button>
      <el-button text size="small" @click="goToPanel">打开面板</el-button>
    </div>

    <!-- 告警内容 -->
    <div v-else-if="alert" class="landing-content">
      <!-- 顶部状态区 -->
      <div class="status-section" :class="statusClass">
        <div v-if="autoFixed" class="auto-fixed-icon">
          <el-icon :size="56" color="#52c41a"><CircleCheckFilled /></el-icon>
        </div>
        <div v-else class="alert-level-icon">
          <el-icon :size="48" :color="levelColor">
            <WarningFilled v-if="alert.level === 'critical' || alert.level === 'error' || alert.level === 'fatal'" />
            <Warning v-else-if="alert.level === 'warning'" />
            <InfoFilled v-else />
          </el-icon>
        </div>
        <h1 class="alert-title">{{ alert.title }}</h1>
        <div v-if="autoFixed" class="auto-fixed-text">
          ✅ 已自动处理，无需操作
        </div>
        <div v-else class="alert-level-text" :style="{ color: levelColor }">
          {{ levelLabel }}
        </div>
        <!-- 双向通知编号 -->
        <div v-if="alert.shortCode" class="short-code-badge">
          编号 <strong>{{ alert.shortCode }}</strong>
          <span class="short-code-hint">回复此编号+指令可远程控制</span>
        </div>
      </div>

      <!-- 信息区 -->
      <div class="info-section">
        <div class="info-row">
          <span class="info-label">📍 服务器</span>
          <span class="info-value">{{ alert.server_name || sourceLabel(alert.source) || '—' }}</span>
        </div>
        <div class="info-row">
          <span class="info-label">⏰ 时间</span>
          <span class="info-value">{{ formatTime(alert.timestamp) }}</span>
        </div>
        <div class="info-row">
          <span class="info-label">🤖 处理状态</span>
          <span class="info-value" :class="statusClass">{{ statusLabel }}</span>
        </div>

        <!-- 人话摘要 -->
        <div v-if="alert.message" class="summary-card">
          <div class="summary-title">📋 事情经过</div>
          <p class="summary-text">{{ alert.message }}</p>
        </div>

        <!-- 根因链 -->
        <div v-if="incident?.chain?.length > 0" class="root-cause-card">
          <div class="summary-title">🔗 根因链</div>
          <div class="chain-container">
            <div v-for="(link, i) in incident.chain" :key="i" class="chain-item">
              <div class="chain-node">{{ link.from }}</div>
              <div class="chain-arrow">↓</div>
              <div class="chain-node chain-node-leaf">{{ link.to }}</div>
              <div class="chain-via">{{ formatVia(link.via) }}</div>
            </div>
          </div>
          <div class="chain-summary">
            {{ incident.chain.length }} 条告警因因果关系被收敛为 1 个事件
          </div>
        </div>

        <!-- 建议动作 -->
        <div v-if="incident?.actions?.length > 0" class="actions-card">
          <div class="summary-title">🔧 建议处置</div>
          <div v-for="(action, i) in incident.actions" :key="i" class="action-row">
            <span class="action-num">{{ i + 1 }}</span>
            <span class="action-text">{{ action }}</span>
          </div>
        </div>

        <!-- 知识库推荐 -->
        <div v-if="recommendation" class="recommend-card">
          <div class="summary-title">📚 历史经验</div>
          <p class="recommend-text">{{ recommendation }}</p>
        </div>

        <!-- LLM AI 解释 -->
        <div class="llm-section">
          <el-button
            :loading="llmLoading"
            @click="fetchLLMExplanation"
            type="primary"
            plain
            size="small"
            style="width: 100%"
          >
            🤖 AI 解释此告警
          </el-button>
          <div v-if="llmExplanation" class="llm-box">{{ llmExplanation }}</div>
        </div>

        <!-- 远程暂停开关 -->
        <div v-if="!autoFixed && alert.shortCode" class="remote-control-card">
          <div class="summary-title">📱 远程控制</div>
          <p class="remote-hint">在手机上回复以下指令：</p>
          <div class="remote-cmd">
            <code>{{ alert.shortCode }}1</code> 暂停自动修复
          </div>
          <div class="remote-cmd">
            <code>{{ alert.shortCode }}2</code> 恢复自动修复
          </div>
          <div class="remote-cmd">
            <code>{{ alert.shortCode }}3</code> 确认告警
          </div>
          <el-button
            v-if="!remotePaused"
            size="small" type="warning" plain style="width: 100%; margin-top: 8px"
            :loading="pausing"
            @click="remotePause"
          >
            ⏸ 一键暂停自动修复
          </el-button>
          <el-button
            v-else
            size="small" type="success" plain style="width: 100%; margin-top: 8px"
            :loading="pausing"
            @click="remoteResume"
          >
            ▶ 恢复自动修复
          </el-button>
          <el-tag v-if="remotePaused" type="warning" effect="dark" style="margin-top: 8px; width: 100%; text-align: center">
            ⏸ 自动修复已暂停
          </el-tag>
        </div>
      </div>

      <!-- 操作按钮区 -->
      <div class="action-section">
        <el-button
          v-if="autoFixed"
          type="success"
          size="large"
          class="landing-btn"
          @click="ackAndClose"
        >
          知道了
        </el-button>
        <template v-else>
          <el-button
            type="primary"
            size="large"
            class="landing-btn"
            @click="ackAlert"
          >
            确认收到
          </el-button>
          <el-button
            size="large"
            class="landing-btn"
            @click="goToDetail"
          >
            查看详情
          </el-button>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import axios from 'axios'
import dayjs from 'dayjs'
import { WarningFilled, CircleCheckFilled, Warning, InfoFilled } from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()

const alert = ref<any>(null)
const incident = ref<any>(null)
const recommendation = ref('')
const llmLoading = ref(false)
const llmExplanation = ref('')
const remotePaused = ref(false)
const pausing = ref(false)
const loading = ref(true)
const error = ref('')

const alertId = computed(() => route.params.id as string)
const token = computed(() => route.query.token as string)

const autoFixed = computed(() => {
  if (!alert.value) return false
  return alert.value.acknowledged || alert.value.message?.includes('已自动')
})

const levelColor = computed(() => {
  const level = alert.value?.level || ''
  if (level === 'critical' || level === 'fatal') return '#ff4d4f'
  if (level === 'error') return '#ff4d4f'
  if (level === 'warning') return '#faad14'
  return '#909399'
})

const levelLabel = computed(() => {
  const level = alert.value?.level || ''
  const labels: Record<string, string> = {
    critical: '🔴 严重',
    error: '🔴 严重',
    fatal: '🔴 致命',
    warning: '🟡 警告',
    info: '🟢 提醒',
  }
  return labels[level] || '🟢 提醒'
})

const statusClass = computed(() => {
  if (autoFixed.value) return 'status-fixed'
  const level = alert.value?.level || ''
  if (level === 'critical' || level === 'error' || level === 'fatal') return 'status-danger'
  if (level === 'warning') return 'status-warning'
  return 'status-normal'
})

const statusLabel = computed(() => {
  if (remotePaused.value) return '⏸ 已暂停自动修复'
  if (autoFixed.value) return '✅ 已自动处理'
  if (alert.value?.acknowledged) return '已确认'
  return '⏳ 待处理'
})

function formatTime(ts: string): string {
  if (!ts) return '—'
  return dayjs(ts).format('MM-DD HH:mm')
}

function formatVia(via: string): string {
  if (!via) return ''
  if (via.startsWith('domain-rule:')) return via.substring(12)
  if (via === 'same-source') return '同源连锁'
  return via
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
  if (!src) return ''
  return sourceLabels[src] || src
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {}
  if (token.value) headers['X-Alert-Token'] = token.value
  return headers
}

async function fetchAlert() {
  loading.value = true
  error.value = ''
  try {
    const resp = await axios.get(`/api/alerts/${alertId.value}`, { headers: authHeaders() })
    alert.value = resp.data

    // 并行获取关联事件、知识库推荐、远程暂停状态
    fetchIncident()
    fetchRecommendation()
    fetchRemoteStatus()
  } catch (err: any) {
    error.value = err?.response?.data?.error || '请检查网络后重试'
  } finally {
    loading.value = false
  }
}

async function fetchIncident() {
  try {
    const resp = await axios.get(`/api/incident-by-alert/${alertId.value}`, { headers: authHeaders() })
    incident.value = resp.data
  } catch {
    incident.value = null
  }
}

async function fetchRecommendation() {
  try {
    const resp = await axios.get(`/api/knowledge/recommend/${alertId.value}`, { headers: authHeaders() })
    recommendation.value = resp.data.recommendation || ''
  } catch {
    recommendation.value = ''
  }
}

async function fetchRemoteStatus() {
  try {
    const resp = await axios.get('/api/safety/status', { headers: authHeaders() })
    remotePaused.value = resp.data.remotePaused || false
  } catch {
    remotePaused.value = false
  }
}

async function fetchLLMExplanation() {
  llmLoading.value = true
  llmExplanation.value = ''
  try {
    const resp = await axios.get(`/api/llm/explain-alert/${alertId.value}`, { headers: authHeaders() })
    if (resp.data.status === 'running') {
      // 后端异步调用 LLM（最长约 30s），轮询等待结果，而不是把"进行中"误显示为失败
      for (let i = 0; i < 15; i++) {
        await new Promise(r => setTimeout(r, 2000))
        if (alertId.value !== resp.config?.url) { llmLoading.value = false; return }
        const r2 = await axios.get(`/api/llm/explain-alert/${alertId.value}`, { headers: authHeaders() })
        if (r2.data.status !== 'running') {
          llmExplanation.value = r2.data.explanation || '无法生成解释'
          llmLoading.value = false
          return
        }
      }
      llmExplanation.value = 'AI 解释生成超时，请稍后刷新重试'
    } else {
      llmExplanation.value = resp.data.explanation || '无法生成解释'
    }
  } catch (err: any) {
    llmExplanation.value = err?.response?.data?.error || 'AI 解释暂时不可用'
  } finally {
    llmLoading.value = false
  }
}

async function remotePause() {
  pausing.value = true
  try {
    await axios.post('/api/safety/remote-pause', {}, { headers: authHeaders() })
    remotePaused.value = true
  } catch {
    // ignore
  } finally {
    pausing.value = false
  }
}

async function remoteResume() {
  pausing.value = true
  try {
    await axios.post('/api/safety/remote-resume', {}, { headers: authHeaders() })
    remotePaused.value = false
  } catch {
    // ignore
  } finally {
    pausing.value = false
  }
}

async function ackAlert() {
  try {
    await axios.post(`/api/alerts/${alertId.value}/ack`, {}, { headers: authHeaders() })
    alert.value.acknowledged = true
  } catch {
    // 即使确认失败，也允许用户继续操作
  }
  goToDetail()
}

function goToDetail() {
  if (token.value) {
    localStorage.setItem('sg_token', token.value)
  }
  router.push('/alerts')
}

function goToPanel() {
  if (token.value) {
    localStorage.setItem('sg_token', token.value)
  }
  router.push('/dashboard')
}

function ackAndClose() {
  if (window.opener) {
    window.close()
  } else {
    goToDetail()
  }
}

onMounted(() => {
  fetchAlert()
})
</script>

<style scoped>
.alert-landing {
  min-height: 100vh;
  min-height: 100dvh;
  background: #f5f7fa;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0;
  max-width: 500px;
  margin: 0 auto;
}

/* 骨架屏 */
.landing-skeleton {
  width: 100%;
  padding: 40px 20px;
  text-align: center;
}
.skeleton-circle {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  background: #e8e8e8;
  margin: 0 auto 20px;
  animation: skeleton-pulse 1.5s ease-in-out infinite;
}
.skeleton-line {
  height: 20px;
  background: #e8e8e8;
  border-radius: 4px;
  margin: 12px auto;
  animation: skeleton-pulse 1.5s ease-in-out infinite;
}
@keyframes skeleton-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

/* 错误状态 */
.landing-error {
  text-align: center;
  padding: 60px 24px;
}
.error-title {
  font-size: 18px;
  color: #303133;
  margin: 16px 0 8px;
}
.error-desc {
  font-size: 14px;
  color: #909399;
  margin-bottom: 24px;
  line-height: 1.6;
}

/* 告警内容 */
.landing-content {
  width: 100%;
  flex: 1;
  display: flex;
  flex-direction: column;
}

/* 顶部状态区 */
.status-section {
  padding: 40px 24px 32px;
  text-align: center;
  background: #fff;
  border-bottom: 1px solid #f0f0f0;
}
.status-section.status-danger {
  background: linear-gradient(180deg, #fff1f0 0%, #fff 100%);
}
.status-section.status-warning {
  background: linear-gradient(180deg, #fffbe6 0%, #fff 100%);
}
.status-section.status-fixed {
  background: linear-gradient(180deg, #f6ffed 0%, #fff 100%);
}

.auto-fixed-icon,
.alert-level-icon {
  margin-bottom: 16px;
}

.alert-title {
  font-size: 20px;
  font-weight: 700;
  color: #303133;
  line-height: 1.5;
  margin: 0 0 12px;
  word-break: break-word;
}

.auto-fixed-text {
  font-size: 16px;
  color: #52c41a;
  font-weight: 600;
}

.alert-level-text {
  font-size: 15px;
  font-weight: 500;
}

/* 双向通知编号 */
.short-code-badge {
  margin-top: 16px;
  display: inline-block;
  background: #e6f7ff;
  border: 1px solid #91d5ff;
  border-radius: 16px;
  padding: 6px 16px;
  font-size: 13px;
  color: #1890ff;
}
.short-code-badge strong {
  font-size: 16px;
  letter-spacing: 1px;
}
.short-code-hint {
  display: block;
  font-size: 11px;
  color: #909399;
  margin-top: 2px;
}

/* 信息区 */
.info-section {
  padding: 20px 16px;
  flex: 1;
}

.info-row {
  display: flex;
  align-items: center;
  padding: 12px 8px;
  border-bottom: 1px solid #f5f5f5;
  font-size: 14px;
}
.info-label {
  color: #909399;
  min-width: 90px;
  flex-shrink: 0;
}
.info-value {
  color: #303133;
  font-weight: 500;
  flex: 1;
  text-align: right;
  word-break: break-word;
}
.info-value.status-danger { color: #ff4d4f; }
.info-value.status-warning { color: #faad14; }
.info-value.status-fixed { color: #52c41a; }

/* 人话摘要卡片 */
.summary-card {
  margin-top: 20px;
  padding: 16px;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #f0f0f0;
}
.summary-title {
  font-size: 14px;
  font-weight: 600;
  color: #606266;
  margin-bottom: 8px;
}
.summary-text {
  font-size: 14px;
  color: #606266;
  line-height: 1.8;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

/* 根因链卡片 */
.root-cause-card {
  margin-top: 16px;
  padding: 16px;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #ffd591;
  background: linear-gradient(180deg, #fffbe6 0%, #fff 100%);
}
.chain-container { display: flex; flex-direction: column; align-items: center; }
.chain-item { display: flex; flex-direction: column; align-items: center; margin-bottom: 8px; }
.chain-node {
  background: #fff; border: 1px solid #e4e7ed; border-radius: 6px;
  padding: 6px 12px; font-size: 13px; font-weight: 500;
}
.chain-node-leaf { border-color: #ff7875; color: #cf1322; }
.chain-arrow { color: #d9d9d9; font-size: 16px; line-height: 1; }
.chain-via { font-size: 11px; color: #e6a23c; font-style: italic; }
.chain-summary {
  margin-top: 12px; text-align: center; font-size: 12px; color: #909399;
}

/* 建议动作卡片 */
.actions-card {
  margin-top: 16px;
  padding: 16px;
  background: #f0f9ff;
  border-radius: 8px;
  border: 1px solid #bae0ff;
}
.action-row {
  display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px;
}
.action-num {
  width: 20px; height: 20px; border-radius: 50%; background: #1890ff;
  color: #fff; font-size: 12px; display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.action-text { font-size: 14px; color: #303133; line-height: 1.6; }

/* 知识库推荐卡片 */
.recommend-card {
  margin-top: 16px;
  padding: 16px;
  background: #f9f0ff;
  border-radius: 8px;
  border: 1px solid #d3adf7;
}
.recommend-text {
  font-size: 14px; color: #606266; line-height: 1.8; margin: 0;
  white-space: pre-wrap;
}

/* LLM AI 解释 */
.llm-section { margin-top: 16px; }
.llm-box {
  margin-top: 12px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: #fff; border-radius: 8px; padding: 16px;
  white-space: pre-wrap; line-height: 1.8; font-size: 14px;
}

/* 远程控制卡片 */
.remote-control-card {
  margin-top: 16px;
  padding: 16px;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #ffc53d;
  background: linear-gradient(180deg, #fffbe6 0%, #fff 100%);
}
.remote-hint { font-size: 13px; color: #909399; margin: 0 0 8px; }
.remote-cmd {
  font-size: 14px; padding: 6px 0; color: #606266;
}
.remote-cmd code {
  background: #f5f5f5; border: 1px solid #d9d9d9; border-radius: 4px;
  padding: 2px 8px; font-family: monospace; font-weight: 600; color: #fa8c16;
  margin-right: 8px;
}

/* 操作按钮区 */
.action-section {
  padding: 16px 16px 32px;
  background: #fff;
  border-top: 1px solid #f0f0f0;
  position: sticky;
  bottom: 0;
  z-index: 10;
}

.landing-btn {
  width: 100%;
  height: 52px;
  font-size: 16px;
  font-weight: 600;
  border-radius: 8px;
  margin-bottom: 12px;
}
.landing-btn:last-child {
  margin-bottom: 0;
}
</style>
