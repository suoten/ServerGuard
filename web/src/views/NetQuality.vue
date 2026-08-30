<template>
  <div class="netquality-page">
    <!-- 标题栏 -->
    <div class="page-header">
      <div class="header-left">
        <h2>网络质量地图</h2>
        <span class="header-sub">延迟探测 · 丢包监控 · 质量评级 · 热力图</span>
      </div>
      <el-button-group>
        <el-button :icon="Refresh" @click="fetchReport" :loading="loading">刷新</el-button>
        <el-button type="primary" :icon="Position" @click="probeNow" :loading="probing">立即探测</el-button>
      </el-button-group>
    </div>

    <!-- 总体评估 -->
    <el-card v-if="report && report.overall" shadow="hover" class="overall-card">
      <div class="overall-content">
        <div class="overall-icon">
          <el-icon :size="32" :color="overallColor"><DataAnalysis /></el-icon>
        </div>
        <div class="overall-text">
          <div class="overall-title">网络质量总评</div>
          <div class="overall-desc">{{ report.overall }}</div>
        </div>
      </div>
    </el-card>

    <!-- 探测结果 -->
    <el-card shadow="hover" style="margin-bottom: 16px">
      <template #header>
        <div class="card-header">
          <span>探测结果</span>
          <span v-if="report" class="probe-time">探测时间: {{ formatTime(report.timestamp) }}</span>
        </div>
      </template>

      <div v-if="report && report.results && report.results.length > 0" class="results-grid">
        <div
          v-for="r in report.results"
          :key="r.target"
          class="probe-card"
          :class="probeCardClass(r)"
        >
          <!-- 评级徽章 -->
          <div class="grade-badge" :class="'grade-' + (r.grade || 'F')">{{ r.grade || '?' }}</div>

          <div class="probe-header">
            <span class="probe-target">{{ r.target }}</span>
            <el-icon v-if="r.alive && r.loss === 0" style="color: #22c55e"><CircleCheckFilled /></el-icon>
            <el-icon v-else-if="r.alive" style="color: #e6a23c"><WarningFilled /></el-icon>
            <el-icon v-else style="color: #f56c6c"><CircleCloseFilled /></el-icon>
          </div>
          <div class="probe-host">{{ r.host || '本地网关' }}</div>

          <div class="probe-metrics">
            <div class="metric">
              <span class="metric-label">平均延迟</span>
              <span class="metric-val" :style="{ color: latencyColor(r.rtt_avg_ms) }">
                {{ r.alive && r.rtt_avg_ms != null && r.rtt_avg_ms > 0 ? r.rtt_avg_ms.toFixed(0) + 'ms' : 'N/A' }}
              </span>
            </div>
            <div class="metric">
              <span class="metric-label">丢包率</span>
              <span class="metric-val" :style="{ color: lossColor(r.loss) }">
                {{ r.loss != null ? r.loss.toFixed(0) + '%' : '0%' }}
              </span>
            </div>
            <div class="metric">
              <span class="metric-label">抖动</span>
              <span class="metric-val" :style="{ color: jitterColor(r.jitter_ms) }">
                {{ r.alive && r.jitter_ms != null ? r.jitter_ms.toFixed(0) + 'ms' : '-' }}
              </span>
            </div>
            <div class="metric">
              <span class="metric-label">跳数</span>
              <span class="metric-val">{{ r.hops || '-' }}</span>
            </div>
          </div>

          <div v-if="r.alive" class="probe-range">
            min {{ r.rtt_min_ms != null ? r.rtt_min_ms.toFixed(0) : '?' }}ms · max {{ r.rtt_max_ms != null ? r.rtt_max_ms.toFixed(0) : '?' }}ms
          </div>
          <div v-if="r.assessment" class="probe-assessment">
            {{ r.assessment }}
          </div>
        </div>
      </div>

      <el-empty v-else description="尚未执行网络探测，点击「立即探测」开始">
        <el-button type="primary" @click="probeNow" :loading="probing">立即探测</el-button>
      </el-empty>
    </el-card>

    <!-- 延迟对比图 -->
    <el-card v-if="report && report.results && report.results.length > 0" shadow="hover" style="margin-bottom: 16px">
      <template #header><span>延迟 / 丢包 / 抖动 对比</span></template>
      <v-chart :option="chartOption" :autoresize="true" style="height: 320px" />
    </el-card>

    <!-- 探测目标 -->
    <el-card shadow="hover">
      <template #header><span>探测目标列表</span></template>
      <el-table :data="targets.slice((targetPage-1)*targetSize, targetPage*targetSize)" size="small" stripe>
        <el-table-column label="#" width="40" type="index" />
        <el-table-column label="名称" prop="name" width="150" />
        <el-table-column label="主机" prop="host" min-width="200" />
        <el-table-column label="说明" prop="comment" min-width="200" />
      </el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="targetPage" v-model:page-size="targetSize" :page-sizes="[10, 20, 50, 100]" :total="targets.length" layout="total, sizes, prev, pager, next" />
</div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, TitleComponent, LegendComponent } from 'echarts/components'
import { Refresh, Position, CircleCheckFilled, CircleCloseFilled, WarningFilled, DataAnalysis } from '@element-plus/icons-vue'
import { useDark } from '@/composables/useDark'

use([CanvasRenderer, BarChart, GridComponent, TooltipComponent, TitleComponent, LegendComponent])

const { isDark } = useDark()

const report = ref<any>(null)
const targets = ref<any[]>([])
const targetPage = ref(1)
const targetSize = ref(10)
const loading = ref(false)
const probing = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

async function fetchReport() {
  loading.value = true
  try {
    const resp = await axios.get('/api/netquality')
    // 后端返回 { status: "completed"|"running"|"idle", report: {...} }
    const data = resp.data
    if (data.report) {
      report.value = data.report
    } else if (data.results) {
      // 兼容直接返回 report 对象的情况
      report.value = data
    }
    // 如果探测正在进行中，自动轮询
    if (data.status === 'running' && !pollTimer) {
      startPolling()
    }
  } catch { /* 静默 */ } finally {
    loading.value = false
  }
}

async function fetchTargets() {
  try {
    const resp = await axios.get('/api/netquality/targets')
    targets.value = resp.data.targets || []
  } catch { /* 静默 */ }
}

async function probeNow() {
  probing.value = true
  try {
    const resp = await axios.post('/api/netquality/probe')
    // 后端返回 202: { status: "started", message: "..." }
    // 或者 409: { status: "running", message: "..." }
    if (resp.data.status === 'started' || resp.data.status === 'running') {
      // 开始轮询结果
      startPolling()
    } else if (resp.data.report) {
      // 意外直接返回了结果
      report.value = resp.data.report
      probing.value = false
    }
  } catch (err: any) {
    // 409 Conflict 也意味着正在运行
    if (err?.response?.status === 409) {
      startPolling()
    } else {
      console.error('探测失败:', err)
      probing.value = false
    }
  }
}

function startPolling() {
  probing.value = true
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(async () => {
    try {
      const resp = await axios.get('/api/netquality')
      const data = resp.data
      if (data.status === 'completed' && data.report) {
        report.value = data.report
        probing.value = false
        stopPolling()
      } else if (data.status === 'running') {
        // 继续等待
      }
    } catch {
      stopPolling()
      probing.value = false
    }
  }, 3000) // 每 3 秒轮询一次

  // 安全超时：2 分钟后停止轮询
  setTimeout(() => {
    if (probing.value) {
      stopPolling()
      probing.value = false
    }
  }, 120000)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

function probeCardClass(r: any): string {
  if (!r.alive) return 'probe-card-danger'
  const grade = r.grade || ''
  if (grade === 'A' || grade === 'B') return 'probe-card-ok'
  if (grade === 'C') return 'probe-card-warning'
  return 'probe-card-danger'
}

const overallColor = computed(() => {
  if (!report.value?.results) return '#909399'
  const grades = report.value.results.map((r: any) => r.grade)
  if (grades.includes('F')) return '#f56c6c'
  if (grades.includes('D') || grades.includes('C')) return '#e6a23c'
  return '#22c55e'
})

function latencyColor(ms: number): string {
  if (!ms || ms === 0) return '#909399'
  if (ms < 50) return '#22c55e'
  if (ms < 150) return '#e6a23c'
  return '#f56c6c'
}

function lossColor(loss: number): string {
  if (!loss || loss === 0) return '#22c55e'
  if (loss < 30) return '#e6a23c'
  return '#f56c6c'
}

function jitterColor(jitter: number): string {
  if (!jitter || jitter === 0) return '#909399'
  if (jitter < 20) return '#22c55e'
  if (jitter < 50) return '#e6a23c'
  return '#f56c6c'
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

const chartOption = computed(() => {
  if (!report.value?.results) return {}
  const results = report.value.results.filter((r: any) => r.alive)
  if (results.length === 0) return {}

  const names = results.map((r: any) => r.target)
  const avgData = results.map((r: any) => r.rtt_avg_ms || 0)
  const lossData = results.map((r: any) => r.loss || 0)
  const jitterData = results.map((r: any) => r.jitter_ms || 0)

  return {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: (params: any) => {
        const name = params[0]?.axisValueLabel || ''
        let html = `${name}`
        for (const p of params) {
          const val = typeof p.value === 'number' ? p.value.toFixed(2) : p.value
          html += `<br/>${p.marker}${p.seriesName}: ${val}`
        }
        return html
      },
    },
    legend: {
      data: ['平均延迟(ms)', '丢包率(%)', '抖动(ms)'],
      top: 0,
      textStyle: { color: isDark.value ? '#ccc' : '#333' },
    },
    grid: { top: 40, right: 20, bottom: 10, left: 60 },
    xAxis: {
      type: 'category',
      data: names,
      axisLabel: { color: isDark.value ? '#ccc' : '#333', fontSize: 12 },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: isDark.value ? '#ccc' : '#333' },
      splitLine: { lineStyle: { color: isDark.value ? '#263152' : '#eee' } },
    },
    series: [
      {
        name: '平均延迟(ms)',
        type: 'bar',
        data: avgData,
        itemStyle: {
          color: (params: any) => {
            const val = params.value
            if (val < 50) return '#22c55e'
            if (val < 150) return '#e6a23c'
            return '#f56c6c'
          },
          borderRadius: [4, 4, 0, 0],
        },
        barWidth: '20%',
      },
      {
        name: '丢包率(%)',
        type: 'bar',
        data: lossData,
        itemStyle: {
          color: '#f56c6c',
          borderRadius: [4, 4, 0, 0],
        },
        barWidth: '20%',
      },
      {
        name: '抖动(ms)',
        type: 'bar',
        data: jitterData,
        itemStyle: {
          color: '#7c93ff',
          borderRadius: [4, 4, 0, 0],
        },
        barWidth: '20%',
      },
    ],
  }
})

onMounted(() => {
  fetchReport()
  fetchTargets()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped>
.netquality-page {
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
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.probe-time {
  font-size: 12px;
  color: var(--sg-text-3);
}

/* 总体评估卡片 */
.overall-card {
  margin-bottom: 16px;
}
.overall-content {
  display: flex;
  align-items: center;
  gap: 16px;
}
.overall-icon {
  flex-shrink: 0;
  padding: 12px;
  border-radius: 12px;
  background: var(--sg-bg-page);
}
.overall-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--sg-text-2);
}
.overall-desc {
  font-size: 16px;
  font-weight: 600;
  color: var(--sg-text-1);
  margin-top: 4px;
}

/* 探测结果网格 */
.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 14px;
}
.probe-card {
  position: relative;
  padding: 16px;
  border-radius: 10px;
  border: 2px solid;
  transition: all 0.25s;
  overflow: hidden;
}
.probe-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
}
.probe-card-ok {
  border-color: #22c55e;
  background: rgba(34, 197, 94, 0.04);
}
.probe-card-warning {
  border-color: #e6a23c;
  background: rgba(230, 162, 60, 0.04);
}
.probe-card-danger {
  border-color: #f56c6c;
  background: rgba(245, 108, 108, 0.04);
}

/* 评级徽章 */
.grade-badge {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  font-weight: 800;
  color: #fff;
}
.grade-A { background: linear-gradient(135deg, #22c55e, #16a34a); }
.grade-B { background: linear-gradient(135deg, #84cc16, #65a30d); }
.grade-C { background: linear-gradient(135deg, #e6a23c, #d97706); }
.grade-D { background: linear-gradient(135deg, #f56c6c, #dc2626); }
.grade-F { background: linear-gradient(135deg, #ef4444, #991b1b); }

.probe-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
  padding-right: 36px;
}
.probe-target {
  font-size: 16px;
  font-weight: 700;
  color: var(--sg-text-1);
}
.probe-host {
  font-size: 12px;
  color: var(--sg-text-3);
  margin-bottom: 12px;
  font-family: monospace;
}
.probe-metrics {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
.metric {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.metric-label {
  font-size: 11px;
  color: var(--sg-text-3);
}
.metric-val {
  font-size: 18px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.probe-range {
  margin-top: 8px;
  font-size: 11px;
  color: var(--sg-text-3);
  font-variant-numeric: tabular-nums;
}
.probe-assessment {
  margin-top: 6px;
  font-size: 12px;
  color: var(--sg-text-2);
  line-height: 1.5;
}
</style>
