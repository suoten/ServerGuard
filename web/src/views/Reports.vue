<template>
  <div class="reports-page">
    <!-- 标题栏 -->
    <div class="page-header">
      <div class="header-left">
        <h2>智能报告</h2>
        <span class="header-sub">故障复盘纪要 · 运维周报</span>
      </div>
    </div>

    <el-tabs v-model="activeTab" class="reports-tabs">
      <!-- ═══ 故障复盘 ═══ -->
      <el-tab-pane label="故障复盘" name="postmortem">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>故障复盘纪要</span>
              <div class="header-actions">
                <el-date-picker
                  v-model="pmTimeRange"
                  type="datetimerange"
                  range-separator="至"
                  start-placeholder="故障开始时间"
                  end-placeholder="故障结束时间"
                  format="YYYY-MM-DD HH:mm"
                  value-format="YYYY-MM-DDTHH:mm:ss"
                  size="small"
                  style="width: 360px"
                />
                <el-button type="primary" size="small" @click="generatePostmortem" :loading="pmLoading">
                  生成复盘报告
                </el-button>
              </div>
            </div>
          </template>

          <div v-if="pmReport" class="pm-report">
            <!-- 概览 -->
            <el-row :gutter="16" style="margin-bottom: 16px">
              <el-col :xs="24" :sm="12">
                <div class="pm-meta">
                  <h3>{{ pmReport.title }}</h3>
                  <el-descriptions :column="1" size="small" border>
                    <el-descriptions-item label="事件 ID">{{ pmReport.incident_id }}</el-descriptions-item>
                    <el-descriptions-item label="严重级别">
                      <el-tag :type="pmSeverityType(pmReport.severity)" size="small">{{ pmReport.severity }}</el-tag>
                    </el-descriptions-item>
                    <el-descriptions-item label="开始时间">{{ formatTime(pmReport.start_time) }}</el-descriptions-item>
                    <el-descriptions-item label="结束时间">{{ formatTime(pmReport.end_time) }}</el-descriptions-item>
                    <el-descriptions-item label="持续时长">{{ pmReport.duration }}</el-descriptions-item>
                  </el-descriptions>
                </div>
              </el-col>
              <el-col :xs="24" :sm="12">
                <el-card shadow="never" class="pm-summary-card">
                  <template #header><span>摘要</span></template>
                  <p class="pm-summary-text">{{ pmReport.summary }}</p>
                </el-card>
              </el-col>
            </el-row>

            <!-- 时间线 -->
            <el-card v-if="pmReport.timeline && pmReport.timeline.length > 0" shadow="never" style="margin-bottom: 16px">
              <template #header><span>事件时间线</span></template>
              <el-timeline>
                <el-timeline-item
                  v-for="(item, i) in pmReport.timeline"
                  :key="i"
                  :timestamp="formatTime(item.timestamp)"
                  :type="timelineItemType(item.type)"
                  placement="top"
                >
                  <span class="timeline-text">{{ item.message }}</span>
                </el-timeline-item>
              </el-timeline>
            </el-card>

            <!-- 根因推测 -->
            <el-card v-if="pmReport.root_cause" shadow="never" style="margin-bottom: 16px">
              <template #header><span>根因推测</span></template>
              <p class="pm-text">{{ pmReport.root_cause }}</p>
            </el-card>

            <!-- 修复动作 -->
            <el-card v-if="pmReport.actions && pmReport.actions.length > 0" shadow="never" style="margin-bottom: 16px">
              <template #header><span>修复动作</span></template>
              <el-table :data="pmReport.actions" size="small" stripe>
                <el-table-column label="时间" width="140">
                  <template #default="{ row }">{{ formatTime(row.time) }}</template>
                </el-table-column>
                <el-table-column label="动作" prop="action" width="120" />
                <el-table-column label="结果" width="80">
                  <template #default="{ row }">
                    <el-tag :type="row.success ? 'success' : 'danger'" size="small">
                      {{ row.success ? '成功' : '失败' }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="详情" prop="message" min-width="300" show-overflow-tooltip />
              </el-table>
            </el-card>

            <!-- 经验教训 -->
            <el-card v-if="pmReport.lessons_learned" shadow="never">
              <template #header><span>经验教训</span></template>
              <p class="pm-text">{{ pmReport.lessons_learned }}</p>
            </el-card>
          </div>

          <el-empty v-else description="选择故障时间范围后点击「生成复盘报告」">
            <el-button type="primary" @click="generatePostmortem" :loading="pmLoading">生成复盘报告</el-button>
          </el-empty>
        </el-card>
      </el-tab-pane>

      <!-- ═══ 运维周报 ═══ -->
      <el-tab-pane label="运维周报" name="weekly">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>运维周报（Markdown）</span>
              <div class="header-actions">
                <el-button size="small" @click="fetchWeekly" :loading="weeklyLoading">
                  <el-icon><Refresh /></el-icon>&nbsp;刷新
                </el-button>
                <el-button type="primary" size="small" @click="sendWeekly" :loading="sendingWeekly">
                  <el-icon><Promotion /></el-icon>&nbsp;推送周报
                </el-button>
              </div>
            </div>
          </template>

          <div v-if="weeklyReport" class="weekly-report">
            <div class="weekly-toolbar">
              <el-button-group>
                <el-button size="small" @click="weeklyView = 'rendered'" :type="weeklyView === 'rendered' ? 'primary' : ''">渲染视图</el-button>
                <el-button size="small" @click="weeklyView = 'markdown'" :type="weeklyView === 'markdown' ? 'primary' : ''">Markdown 源码</el-button>
              </el-button-group>
              <el-button size="small" @click="copyMarkdown" :icon="CopyDocument">复制</el-button>
            </div>

            <!-- Markdown 渲染 -->
            <div v-if="weeklyView === 'rendered'" class="markdown-body" v-html="renderedMarkdown"></div>

            <!-- 源码 -->
            <el-input
              v-else
              type="textarea"
              :model-value="weeklyReport"
              :rows="30"
              readonly
              class="markdown-source"
            />
          </div>

          <el-empty v-else description="点击「刷新」获取周报">
            <el-button type="primary" @click="fetchWeekly" :loading="weeklyLoading">获取周报</el-button>
          </el-empty>
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { ElMessage } from 'element-plus'
import { Refresh, Promotion, CopyDocument } from '@element-plus/icons-vue'

const activeTab = ref('postmortem')

// ── 故障复盘 ──
const pmReport = ref<any>(null)
const pmLoading = ref(false)
const pmTimeRange = ref<[string, string] | null>(null)

// ── 周报 ──
const weeklyReport = ref<string>('')
const weeklyLoading = ref(false)
const sendingWeekly = ref(false)
const weeklyView = ref<'rendered' | 'markdown'>('rendered')

async function generatePostmortem() {
  pmLoading.value = true
  try {
    let start: string
    let end: string

    if (pmTimeRange.value && pmTimeRange.value[0]) {
      start = pmTimeRange.value[0]
      end = pmTimeRange.value[1] || dayjs().format('YYYY-MM-DDTHH:mm:ss')
    } else {
      // 默认最近 1 小时
      start = dayjs().subtract(1, 'hour').format('YYYY-MM-DDTHH:mm:ss')
      end = dayjs().format('YYYY-MM-DDTHH:mm:ss')
    }

    const resp = await axios.post('/api/report/postmortem/generate', { start, end })
    pmReport.value = resp.data
  } catch (err: any) {
    ElMessage.error('生成复盘报告失败: ' + (err?.response?.data?.error || err.message))
  } finally {
    pmLoading.value = false
  }
}

function pmSeverityType(sev: string): string {
  switch (sev) {
    case 'critical': case 'fatal': return 'danger'
    case 'warning': case 'error': return 'warning'
    case 'info': return 'info'
    default: return 'info'
  }
}

function timelineItemType(type: string): string {
  switch (type) {
    case 'alert': return 'danger'
    case 'action': return 'warning'
    case 'recovery': return 'success'
    case 'audit': return 'info'
    default: return 'info'
  }
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

// ── 周报 ──
async function fetchWeekly() {
  weeklyLoading.value = true
  try {
    const resp = await axios.get('/api/report/weekly')
    weeklyReport.value = resp.data.report || ''
  } catch (err: any) {
    ElMessage.error('获取周报失败: ' + (err?.response?.data?.error || err.message))
  } finally {
    weeklyLoading.value = false
  }
}

async function sendWeekly() {
  sendingWeekly.value = true
  try {
    const resp = await axios.post('/api/report/weekly/send')
    ElMessage.success(resp.data.message || '周报已推送')
  } catch (err: any) {
    ElMessage.error('推送失败: ' + (err?.response?.data?.error || err.message))
  } finally {
    sendingWeekly.value = false
  }
}

function copyMarkdown() {
  if (!weeklyReport.value) return
  navigator.clipboard.writeText(weeklyReport.value).then(() => {
    ElMessage.success('已复制到剪贴板')
  }).catch(() => {
    ElMessage.error('复制失败')
  })
}

// 简易 Markdown 渲染
const renderedMarkdown = computed(() => {
  if (!weeklyReport.value) return ''
  let html = weeklyReport.value
  // 转义 HTML
  html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  // 标题
  html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>')
  html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>')
  html = html.replace(/^# (.+)$/gm, '<h2>$1</h2>')
  // 引用
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>')
  // 表格（简化处理）
  html = html.replace(/\|(.+)\|/g, (match) => {
    const cells = match.split('|').filter((c) => c.trim())
    if (cells.every((c) => /^[-: ]+$/.test(c.trim()))) return ''
    const tds = cells.map((c) => `<td>${c.trim()}</td>`).join('')
    return `<tr>${tds}</tr>`
  })
  html = html.replace(/(<tr>[\s\S]*?<\/tr>)/g, '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;margin:8px 0">$1</table>')
  // 列表
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>')
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>')
  // 加粗
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
  // 分隔线
  html = html.replace(/^---$/gm, '<hr/>')
  // 换行
  html = html.replace(/\n\n/g, '</p><p>')
  html = '<p>' + html + '</p>'
  // 清理空标签
  html = html.replace(/<p>\s*<\/p>/g, '')
  return html
})

onMounted(() => {
  // 默认不自动加载，等用户点击
})
</script>

<style scoped>
.reports-page {
  max-width: 1400px;
  margin: 0 auto;
}
.page-header {
  margin-bottom: 16px;
}
.header-left h2 {
  font-size: 20px;
  margin: 0;
}
.header-sub {
  font-size: 13px;
  color: var(--sg-text-3);
  margin-left: 8px;
}
.reports-tabs {
  min-height: 400px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.header-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}
.pm-report {
  animation: fade-in 0.3s ease;
}
@keyframes fade-in {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
.pm-meta h3 {
  font-size: 18px;
  margin: 0 0 12px 0;
  color: var(--sg-text-1);
}
.pm-summary-card {
  height: 100%;
}
.pm-summary-text {
  font-size: 14px;
  line-height: 1.7;
  color: var(--sg-text-2);
}
.timeline-text {
  font-size: 13px;
  color: var(--sg-text-2);
}
.pm-text {
  font-size: 14px;
  line-height: 1.8;
  color: var(--sg-text-2);
}
.weekly-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.markdown-body {
  font-size: 14px;
  line-height: 1.8;
  color: var(--sg-text-2);
  padding: 16px;
  background: var(--sg-bg-card);
  border: 1px solid var(--sg-border);
  border-radius: 8px;
  overflow-x: auto;
}
.markdown-body :deep(h2) {
  font-size: 18px;
  margin: 16px 0 8px;
  color: var(--sg-text-1);
}
.markdown-body :deep(h3) {
  font-size: 16px;
  margin: 14px 0 6px;
  color: var(--sg-text-1);
}
.markdown-body :deep(h4) {
  font-size: 14px;
  margin: 12px 0 4px;
  color: var(--sg-text-2);
}
.markdown-body :deep(blockquote) {
  border-left: 3px solid var(--sg-primary);
  padding: 4px 12px;
  margin: 8px 0;
  color: var(--sg-text-3);
  background: rgba(76, 111, 255, 0.04);
}
.markdown-body :deep(table) {
  font-size: 13px;
  margin: 8px 0;
}
.markdown-body :deep(td) {
  color: var(--sg-text-2);
}
.markdown-body :deep(ul) {
  padding-left: 20px;
  margin: 8px 0;
}
.markdown-body :deep(li) {
  margin: 4px 0;
}
.markdown-body :deep(strong) {
  color: var(--sg-text-1);
}
.markdown-body :deep(hr) {
  border: none;
  border-top: 1px solid var(--sg-border);
  margin: 16px 0;
}
.markdown-source :deep(.el-textarea__inner) {
  font-family: 'Courier New', monospace;
  font-size: 13px;
}
</style>
