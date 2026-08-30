<template>
  <div class="apm-page">
    <!-- 标题栏 -->
    <div class="page-header">
      <div class="header-left">
        <h2>APM 性能监控</h2>
        <span class="header-sub">Nginx 日志分析 · SQL 慢查询 · Redis 大 Key</span>
      </div>
      <el-button-group>
        <el-button :icon="Refresh" @click="refreshAll" :loading="anyLoading">刷新全部</el-button>
      </el-button-group>
    </div>

    <!-- Tab 切换 -->
    <el-tabs v-model="activeTab" class="apm-tabs">
      <!-- ═══ Nginx 日志分析 ═══ -->
      <el-tab-pane label="Nginx 日志分析" name="nginx">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>Nginx 访问日志分析</span>
              <el-button type="primary" size="small" @click="analyzeNginx" :loading="nginxLoading">
                <el-icon><VideoPlay /></el-icon>&nbsp;立即分析
              </el-button>
            </div>
          </template>

          <div v-if="nginxStats" class="nginx-stats">
            <!-- 概览数字 -->
            <el-row :gutter="16">
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box">
                  <div class="stat-val">{{ nginxStats.pv }}</div>
                  <div class="stat-label">PV 页面浏览</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box">
                  <div class="stat-val">{{ nginxStats.uv }}</div>
                  <div class="stat-label">UV 独立访客</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box" :class="{ 'stat-danger': nginxStats.error_rate > 5 }">
                  <div class="stat-val">{{ nginxStats.error_rate.toFixed(1) }}%</div>
                  <div class="stat-label">错误率 ({{ nginxStats.error_count }}次)</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box" :class="{ 'stat-warning': nginxStats.slow_rate > 10 }">
                  <div class="stat-val">{{ nginxStats.slow_rate.toFixed(1) }}%</div>
                  <div class="stat-label">慢请求率 ({{ nginxStats.slow_requests }}次)</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box">
                  <div class="stat-val">{{ nginxStats.crawler_count }}</div>
                  <div class="stat-label">爬虫请求</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6" :md="4">
                <div class="stat-box">
                  <div class="stat-val" style="font-size: 14px; word-break: break-all;">
                    {{ nginxStats.site_name || (nginxStats.log_file ? nginxStats.log_file.split('/').pop() : '-') }}
                  </div>
                  <div class="stat-label">站点 / 日志文件</div>
                </div>
              </el-col>
            </el-row>

            <!-- 分析耗时 -->
            <div v-if="nginxStats.analyze_ms" class="analyze-meta">
              <el-tag size="small" type="info" effect="plain">
                分析 {{ nginxStats.analyzed_lines }} 行 · 耗时 {{ nginxStats.analyze_ms }}ms
              </el-tag>
            </div>

            <!-- 日志文件列表 -->
            <div v-if="nginxStats.log_files && nginxStats.log_files.length > 0" class="section-block">
              <h4>📄 日志文件（{{ nginxStats.log_files.length }} 个）</h4>
              <el-table :data="nginxStats.log_files?.slice((logFilePage-1)*logFileSize, logFilePage*logFileSize) || []" size="small" stripe>
                <el-table-column label="站点" width="120">
                  <template #default="{ row }">
                    <el-tag size="small" type="info">{{ row.site }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="文件路径" min-width="300">
                  <template #default="{ row }">
                    <code class="log-path">{{ row.path }}</code>
                  </template>
                </el-table-column>
                <el-table-column label="大小" width="90" align="right">
                  <template #default="{ row }">{{ formatFileSize(row.size) }}</template>
                </el-table-column>
                <el-table-column label="修改时间" width="150">
                  <template #default="{ row }">{{ row.mod_time || '-' }}</template>
                </el-table-column>
                <el-table-column label="分析行数" width="80" align="right" prop="lines" />
                <el-table-column label="操作" width="80" align="center">
                  <template #default="{ row }">
                    <el-button size="small" type="primary" link @click="tailLogFile(row.path)">
                      <el-icon><View /></el-icon>&nbsp;查看
                    </el-button>
                  </template>
                </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="logFilePage" v-model:page-size="logFileSize" :page-sizes="[10, 20, 50, 100]" :total="(nginxStats.log_files || []).length" layout="total, sizes, prev, pager, next" />
</div>
            </div>

            <div v-if="nginxStats.insights && nginxStats.insights.length > 0" class="section-block">
              <h4>💡 智能洞察</h4>
              <el-alert
                v-for="(insight, idx) in nginxStats.insights"
                :key="idx"
                :type="insightType(insight)"
                :closable="false"
                show-icon
                style="margin-bottom: 8px"
              >
                {{ insight }}
              </el-alert>
            </div>

            <!-- 状态码分布 -->
            <div v-if="nginxStats.status_breakdown && Object.keys(nginxStats.status_breakdown).length > 0" class="section-block">
              <h4>状态码分布</h4>
              <div class="status-codes">
                <el-tag
                  v-for="(count, code) in nginxStats.status_breakdown"
                  :key="code"
                  :type="statusTagType(String(code))"
                  class="status-tag"
                >
                  {{ code }}: {{ count }}
                </el-tag>
              </div>
            </div>

            <!-- 错误详情 -->
            <div v-if="nginxStats.error_details && nginxStats.error_details.length > 0" class="section-block">
              <h4>🔴 错误详情分析（共 {{ nginxStats.error_details.length }} 个错误 URI）</h4>
              <el-table :data="nginxStats.error_details?.slice((nginxErrorPage-1)*nginxErrorSize, nginxErrorPage*nginxErrorSize) || []" size="small" stripe max-height="350">
                <el-table-column label="状态码" width="70" align="center">
                  <template #default="{ row }">
                    <el-tag :type="statusTagType(row.status_code)" size="small">{{ row.status_code }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="URI" prop="uri" min-width="200" show-overflow-tooltip />
                <el-table-column label="次数" prop="count" width="60" align="right" />
                <el-table-column label="错误原因" min-width="180" show-overflow-tooltip>
                  <template #default="{ row }">
                    <span style="color: var(--sg-danger); font-size: 12px;">{{ row.reason }}</span>
                  </template>
                </el-table-column>
                <el-table-column label="修复建议" min-width="250" show-overflow-tooltip>
                  <template #default="{ row }">
                    <span style="color: var(--sg-text-2); font-size: 12px;">{{ row.suggestion }}</span>
                  </template>
                </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="nginxErrorPage" v-model:page-size="nginxErrorSize" :page-sizes="[10, 20, 50, 100]" :total="(nginxStats.error_details || []).length" layout="total, sizes, prev, pager, next" />
</div>
            </div>

            <!-- Top URI & Top IP -->
            <el-row :gutter="16">
              <el-col :xs="24" :md="12">
                <div class="section-block">
                  <h4>热门 URI TOP 10</h4>
                  <el-table :data="nginxStats.top_uris || []" size="small" stripe max-height="300">
                    <el-table-column label="#" width="40" type="index" />
                    <el-table-column label="URI" prop="uri" min-width="200" show-overflow-tooltip />
                    <el-table-column label="请求数" prop="count" width="80" align="right" />
                    <el-table-column label="错误" prop="error_count" width="60" align="right">
                      <template #default="{ row }">
                        <span :style="{ color: row.error_count > 0 ? '#f56c6c' : '#909399' }">{{ row.error_count }}</span>
                      </template>
                    </el-table-column>
                  </el-table>
                </div>
              </el-col>

              <!-- Top IP -->
              <el-col :xs="24" :md="12">
                <div class="section-block">
                  <h4>热门 IP TOP 10</h4>
                  <el-table :data="nginxStats.top_ips || []" size="small" stripe max-height="300">
                    <el-table-column label="#" width="40" type="index" />
                    <el-table-column label="IP 地址" prop="ip" min-width="160" />
                    <el-table-column label="请求数" prop="count" width="100" align="right" />
                  </el-table>
                </div>
              </el-col>
            </el-row>

            <!-- Top UA -->
            <div v-if="nginxStats.top_uas && nginxStats.top_uas.length > 0" class="section-block">
              <h4>热门 User-Agent</h4>
              <el-table :data="nginxStats.top_uas" size="small" stripe max-height="200">
                <el-table-column label="#" width="40" type="index" />
                <el-table-column label="User-Agent" prop="ua" min-width="400" show-overflow-tooltip />
                <el-table-column label="请求数" prop="count" width="100" align="right" />
              </el-table>
            </div>

            <div class="analyze-time">
              分析时间: {{ formatTime(nginxStats.timestamp) }}
            </div>
          </div>

          <el-empty v-else description="尚未执行分析，点击「立即分析」按钮开始">
            <el-button type="primary" @click="analyzeNginx" :loading="nginxLoading">立即分析</el-button>
          </el-empty>
        </el-card>
      </el-tab-pane>

      <!-- ═══ SQL 慢查询 ═══ -->
      <el-tab-pane label="SQL 慢查询" name="slowquery">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>数据库慢查询分析</span>
              <el-button type="primary" size="small" @click="analyzeSlowQuery" :loading="slowQueryLoading">
                <el-icon><VideoPlay /></el-icon>&nbsp;立即分析
              </el-button>
            </div>
          </template>

          <div v-if="slowQueryReport" class="slow-query-stats">
            <el-row :gutter="16">
              <el-col :xs="12" :sm="8">
                <div class="stat-box">
                  <div class="stat-val">{{ slowQueryReport.total_slow }}</div>
                  <div class="stat-label">慢查询总数</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="8">
                <div class="stat-box">
                  <div class="stat-val" style="font-size: 16px;">{{ slowQueryReport.database || '-' }}</div>
                  <div class="stat-label">数据库类型</div>
                </div>
              </el-col>
              <el-col :xs="24" :sm="8">
                <div class="stat-box">
                  <div class="stat-val" style="font-size: 12px; word-break: break-all;">{{ slowQueryReport.log_file || '-' }}</div>
                  <div class="stat-label">日志文件</div>
                </div>
              </el-col>
            </el-row>

            <el-table :data="(slowQueryReport.queries || []).slice((slowQueryPage-1)*slowQuerySize, slowQueryPage*slowQuerySize)" stripe style="margin-top: 16px">
              <el-table-column label="严重度" width="80">
                <template #default="{ row }">
                  <el-tag :type="severityTagType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="SQL 语句" min-width="400" show-overflow-tooltip>
                <template #default="{ row }">
                  <code class="sql-code">{{ row.query }}</code>
                </template>
              </el-table-column>
              <el-table-column label="出现次数" prop="count" width="90" align="right" />
              <el-table-column label="平均耗时" width="100" align="right">
                <template #default="{ row }">
                  <span :style="{ color: row.avg_time_ms > 5000 ? '#f56c6c' : row.avg_time_ms > 1000 ? '#e6a23c' : '#67c23a' }">
                    {{ row.avg_time_ms.toFixed(0) }}ms
                  </span>
                </template>
              </el-table-column>
              <el-table-column label="最大耗时" width="100" align="right">
                <template #default="{ row }">{{ row.max_time_ms.toFixed(0) }}ms</template>
              </el-table-column>
              <el-table-column label="优化建议" min-width="300" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="suggestion-text">{{ row.suggestion }}</span>
                </template>
              </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="slowQueryPage" v-model:page-size="slowQuerySize" :page-sizes="[10, 20, 50, 100]" :total="(slowQueryReport.queries || []).length" layout="total, sizes, prev, pager, next" />
</div>

            <div class="analyze-time">
              分析时间: {{ formatTime(slowQueryReport.timestamp) }}
            </div>
          </div>

          <el-empty v-else description="尚未执行慢查询分析">
            <el-button type="primary" @click="analyzeSlowQuery" :loading="slowQueryLoading">立即分析</el-button>
          </el-empty>
        </el-card>
      </el-tab-pane>

      <!-- ═══ Redis 大 Key ═══ -->
      <el-tab-pane label="Redis 大 Key" name="redis">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>Redis 大 Key / 热 Key 治理</span>
              <el-button type="primary" size="small" @click="analyzeRedis" :loading="redisLoading">
                <el-icon><VideoPlay /></el-icon>&nbsp;立即分析
              </el-button>
            </div>
          </template>

          <div v-if="redisReport" class="redis-stats">
            <el-row :gutter="16">
              <el-col :xs="12" :sm="6">
                <div class="stat-box">
                  <div class="stat-val">
                    <el-icon v-if="redisReport.connected" style="color:#22c55e"><CircleCheckFilled /></el-icon>
                    <el-icon v-else style="color:#f56c6c"><CircleCloseFilled /></el-icon>
                  </div>
                  <div class="stat-label">{{ redisReport.connected ? '已连接' : '未连接' }}</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6">
                <div class="stat-box">
                  <div class="stat-val">{{ redisReport.total_keys || 0 }}</div>
                  <div class="stat-label">总 Key 数</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6">
                <div class="stat-box">
                  <div class="stat-val">{{ formatMem(redisReport.used_memory) }}</div>
                  <div class="stat-label">已用内存</div>
                </div>
              </el-col>
              <el-col :xs="12" :sm="6">
                <div class="stat-box" :class="{ 'stat-danger': (redisReport.big_keys || []).length > 0 }">
                  <div class="stat-val">{{ (redisReport.big_keys || []).length }}</div>
                  <div class="stat-label">大 Key 数</div>
                </div>
              </el-col>
            </el-row>

            <el-table :data="(redisReport.big_keys || []).slice((redisBigKeyPage-1)*redisBigKeySize, redisBigKeyPage*redisBigKeySize)" stripe style="margin-top: 16px">
              <el-table-column label="严重度" width="80">
                <template #default="{ row }">
                  <el-tag :type="severityTagType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Key" prop="key" min-width="200" show-overflow-tooltip />
              <el-table-column label="类型" prop="type" width="80" />
              <el-table-column label="大小" width="120" align="right">
                <template #default="{ row }">{{ formatRedisSize(row.size, row.type) }}</template>
              </el-table-column>
              <el-table-column label="内存" width="120" align="right">
                <template #default="{ row }">{{ formatMem(row.memory_bytes) }}</template>
              </el-table-column>
              <el-table-column label="拆分建议" min-width="300" show-overflow-tooltip>
                <template #default="{ row }">
                  <span class="suggestion-text">{{ row.suggestion }}</span>
                </template>
              </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="redisBigKeyPage" v-model:page-size="redisBigKeySize" :page-sizes="[10, 20, 50, 100]" :total="(redisReport.big_keys || []).length" layout="total, sizes, prev, pager, next" />
</div>

            <div class="analyze-time">
              分析时间: {{ formatTime(redisReport.timestamp) }}
            </div>
          </div>

          <el-empty v-else description="尚未执行 Redis 分析">
            <el-button type="primary" @click="analyzeRedis" :loading="redisLoading">立即分析</el-button>
          </el-empty>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 日志查看对话框 -->
    <el-dialog
      v-model="logDialogVisible"
      :title="'日志查看 — ' + (logDialogPath ? logDialogPath.split('/').pop() : '')"
      width="80%"
      top="5vh"
    >
      <div class="log-dialog-header">
        <code class="log-dialog-path">{{ logDialogPath }}</code>
        <div class="log-dialog-actions">
          <el-select v-model="logLineCount" size="small" style="width: 120px" @change="tailLogFile(logDialogPath)">
            <el-option :value="50" label="50 行" />
            <el-option :value="100" label="100 行" />
            <el-option :value="200" label="200 行" />
            <el-option :value="500" label="500 行" />
          </el-select>
          <el-button size="small" @click="copyLogPath(logDialogPath)">
            <el-icon><CopyDocument /></el-icon>&nbsp;复制路径
          </el-button>
          <el-button size="small" type="primary" @click="tailLogFile(logDialogPath)" :loading="logDialogLoading">
            <el-icon><Refresh /></el-icon>&nbsp;刷新
          </el-button>
        </div>
      </div>
      <div v-loading="logDialogLoading" class="log-content">
        <div v-for="(line, idx) in logDialogLines" :key="idx" class="log-line">
          <span class="log-line-num">{{ idx + 1 }}</span>
          <span class="log-line-text" v-html="colorizeLogLine(line)"></span>
        </div>
        <div v-if="!logDialogLoading && logDialogLines.length === 0" class="log-empty">
          日志文件为空
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { Refresh, VideoPlay, CircleCheckFilled, CircleCloseFilled, View, CopyDocument } from '@element-plus/icons-vue'

// 分页状态
const nginxErrorPage = ref(1)
const nginxErrorSize = ref(10)
const slowQueryPage = ref(1)
const slowQuerySize = ref(10)
const redisBigKeyPage = ref(1)
const redisBigKeySize = ref(10)
const logFilePage = ref(1)
const logFileSize = ref(10)

const activeTab = ref('nginx')

const nginxStats = ref<any>(null)
const slowQueryReport = ref<any>(null)
const redisReport = ref<any>(null)

const nginxLoading = ref(false)
const slowQueryLoading = ref(false)
const redisLoading = ref(false)

const anyLoading = computed(() => nginxLoading.value || slowQueryLoading.value || redisLoading.value)

async function fetchNginxStats() {
  try {
    const resp = await axios.get('/api/apm/nginx')
    if (resp.data.stats !== null && resp.data.stats !== undefined) {
      nginxStats.value = resp.data.stats || resp.data
    } else if (resp.data.timestamp) {
      nginxStats.value = resp.data
    }
  } catch { /* 静默 */ }
}

async function analyzeNginx() {
  nginxLoading.value = true
  try {
    const resp = await axios.post('/api/apm/nginx/analyze')
    nginxStats.value = resp.data
  } catch (err: any) {
    console.error('Nginx 分析失败:', err)
  } finally {
    nginxLoading.value = false
  }
}

async function fetchSlowQuery() {
  try {
    const resp = await axios.get('/api/apm/slow-query')
    if (resp.data.report !== null && resp.data.report !== undefined) {
      slowQueryReport.value = resp.data.report || resp.data
    } else if (resp.data.timestamp) {
      slowQueryReport.value = resp.data
    }
  } catch { /* 静默 */ }
}

async function analyzeSlowQuery() {
  slowQueryLoading.value = true
  try {
    const resp = await axios.post('/api/apm/slow-query/analyze')
    slowQueryReport.value = resp.data
  } catch (err: any) {
    console.error('慢查询分析失败:', err)
  } finally {
    slowQueryLoading.value = false
  }
}

async function fetchRedis() {
  try {
    const resp = await axios.get('/api/apm/redis')
    if (resp.data.report !== null && resp.data.report !== undefined) {
      redisReport.value = resp.data.report || resp.data
    } else if (resp.data.timestamp) {
      redisReport.value = resp.data
    }
  } catch { /* 静默 */ }
}

async function analyzeRedis() {
  redisLoading.value = true
  try {
    const resp = await axios.post('/api/apm/redis/analyze')
    redisReport.value = resp.data
  } catch (err: any) {
    console.error('Redis 分析失败:', err)
  } finally {
    redisLoading.value = false
  }
}

async function refreshAll() {
  await Promise.all([fetchNginxStats(), fetchSlowQuery(), fetchRedis()])
}

function statusTagType(code: string): string {
  if (code.startsWith('2')) return 'success'
  if (code.startsWith('3')) return 'info'
  if (code.startsWith('4')) return 'warning'
  if (code.startsWith('5')) return 'danger'
  return 'info'
}

function severityTagType(sev: string): string {
  switch (sev) {
    case 'high': return 'danger'
    case 'medium': return 'warning'
    case 'low': return 'info'
    default: return 'info'
  }
}

function severityLabel(sev: string): string {
  switch (sev) {
    case 'high': return '高危'
    case 'medium': return '中等'
    case 'low': return '低'
    default: return sev
  }
}

function insightType(insight: string): string {
  if (insight.includes('正常') || insight.includes('未发现异常')) return 'success'
  if (insight.includes('严重') || insight.includes('宕机') || insight.includes('立即')) return 'error'
  if (insight.includes('偏高') || insight.includes('建议') || insight.includes('占比')) return 'warning'
  return 'info'
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

function formatMem(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function formatRedisSize(size: number, type: string): string {
  if (type === 'string') return formatMem(size)
  return size + ' items'
}

onMounted(() => {
  refreshAll()
})

// 日志查看对话框
const logDialogVisible = ref(false)
const logDialogPath = ref('')
const logDialogLines = ref<string[]>([])
const logDialogLoading = ref(false)
const logLineCount = ref(100)

async function tailLogFile(path: string) {
  logDialogPath.value = path
  logDialogVisible.value = true
  logDialogLoading.value = true
  try {
    const resp = await axios.get('/api/apm/nginx/tail', {
      params: { path, lines: logLineCount.value }
    })
    logDialogLines.value = resp.data.lines || []
  } catch (err: any) {
    logDialogLines.value = ['读取失败: ' + (err?.response?.data?.error || err.message)]
  } finally {
    logDialogLoading.value = false
  }
}

function formatFileSize(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function copyLogPath(path: string) {
  navigator.clipboard.writeText(path)
  // 使用 ElMessage 提示
  import('element-plus').then(({ ElMessage }) => {
    ElMessage.success('路径已复制: ' + path)
  })
}

// 日志行着色
function colorizeLogLine(line: string): string {
  // 转义 HTML
  let s = line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  // 状态码着色
  s = s.replace(/" (\d{3}) /g, (match, code) => {
    const c = parseInt(code)
    let color = '#22c55e'
    if (c >= 500) color = '#f56c6c'
    else if (c >= 400) color = '#e6a23c'
    else if (c >= 300) color = '#909399'
    return `" <span style="color:${color};font-weight:600">${code}</span> `
  })
  // IP 地址着色
  s = s.replace(/^(\d+\.\d+\.\d+\.\d+)/, '<span style="color:#7c93ff">$1</span>')
  // HTTP 方法着色
  s = s.replace(/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)/, '"<span style="color:#e6a23c;font-weight:600">$1</span>')
  return s
}
</script>

<style scoped>
.apm-page {
  max-width: 1400px;
  margin: 0 auto;
}
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
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
.apm-tabs {
  min-height: 400px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.stat-box {
  text-align: center;
  padding: 16px 12px;
  border-radius: 10px;
  background: var(--sg-bg-card);
  border: 1px solid var(--sg-border);
  transition: all 0.25s;
}
.stat-box:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(15, 23, 42, 0.06);
}
.stat-box.stat-danger {
  border-color: #f56c6c;
  background: rgba(245, 108, 108, 0.04);
}
.stat-box.stat-warning {
  border-color: #e6a23c;
  background: rgba(230, 162, 60, 0.04);
}
.stat-val {
  font-size: 28px;
  font-weight: 700;
  color: var(--sg-text-1);
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
}
.stat-label {
  font-size: 12px;
  color: var(--sg-text-3);
  margin-top: 4px;
}
.analyze-meta {
  margin-top: 12px;
  display: flex;
  gap: 8px;
}
.section-block {
  margin-top: 20px;
}
.section-block h4 {
  font-size: 14px;
  font-weight: 600;
  color: var(--sg-text-2);
  margin-bottom: 10px;
}
.status-codes {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.status-tag {
  font-size: 13px;
  padding: 4px 12px;
}
.sql-code {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: var(--sg-text-2);
  background: var(--sg-bg-page);
  padding: 2px 6px;
  border-radius: 4px;
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.suggestion-text {
  font-size: 13px;
  color: var(--sg-text-2);
}
.analyze-time {
  margin-top: 16px;
  font-size: 12px;
  color: var(--sg-text-3);
  text-align: right;
}

/* 日志文件路径样式 */
.log-path {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: var(--sg-primary);
  background: var(--sg-bg-page);
  padding: 2px 6px;
  border-radius: 4px;
}

/* 日志查看对话框 */
.log-dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  gap: 12px;
}
.log-dialog-path {
  font-family: 'Courier New', monospace;
  font-size: 12px;
  color: var(--sg-primary);
  background: var(--sg-bg-page);
  padding: 4px 10px;
  border-radius: 6px;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.log-dialog-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}
.log-content {
  max-height: 60vh;
  overflow-y: auto;
  background: #0d1424;
  border-radius: 8px;
  padding: 12px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
}
.log-line {
  display: flex;
  gap: 8px;
  padding: 1px 0;
}
.log-line:hover {
  background: rgba(255, 255, 255, 0.04);
}
.log-line-num {
  color: #4a5568;
  text-align: right;
  min-width: 40px;
  user-select: none;
  flex-shrink: 0;
}
.log-line-text {
  color: #c8d3e0;
  word-break: break-all;
  white-space: pre-wrap;
}
.log-empty {
  color: #64748b;
  text-align: center;
  padding: 40px 0;
}
</style>
