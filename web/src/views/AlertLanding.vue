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
      </div>

      <!-- 信息区 -->
      <div class="info-section">
        <div class="info-row">
          <span class="info-label">📍 服务器</span>
          <span class="info-value">{{ alert.server_name || alert.source || '—' }}</span>
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
const loading = ref(true)
const error = ref('')

const alertId = computed(() => route.params.id as string)
const token = computed(() => route.query.token as string)

const autoFixed = computed(() => {
  if (!alert.value) return false
  // 如果告警已被确认或消息包含"已自动"则认为是自动修复
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
  if (autoFixed.value) return '✅ 已自动处理'
  if (alert.value?.acknowledged) return '已确认'
  return '⏳ 待处理'
})

function formatTime(ts: string): string {
  if (!ts) return '—'
  return dayjs(ts).format('MM-DD HH:mm')
}

async function fetchAlert() {
  loading.value = true
  error.value = ''
  try {
    // 带免登录 token
    const headers: Record<string, string> = {}
    if (token.value) headers['X-Alert-Token'] = token.value

    const resp = await axios.get(`/api/alerts/${alertId.value}`, { headers })
    alert.value = resp.data
  } catch (err: any) {
    error.value = err?.response?.data?.error || '请检查网络后重试'
  } finally {
    loading.value = false
  }
}

async function ackAlert() {
  try {
    const headers: Record<string, string> = {}
    if (token.value) headers['X-Alert-Token'] = token.value
    await axios.post(`/api/alerts/${alertId.value}/ack`, {}, { headers })
    alert.value.acknowledged = true
  } catch {
    // 即使确认失败，也允许用户继续操作
  }
  goToDetail()
}

function goToDetail() {
  // 跳转到完整面板的告警详情页
  if (token.value) {
    localStorage.setItem('sg_token', token.value)
  }
  router.push('/alerts')
}

function goToPanel() {
  // 跳转到主面板
  if (token.value) {
    localStorage.setItem('sg_token', token.value)
  }
  router.push('/dashboard')
}

function ackAndClose() {
  // 已自动修复的告警，用户点"知道了"后直接关闭
  if (window.opener) {
    window.close()
  } else {
    // 微信内置浏览器无法关闭，跳转面板
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
