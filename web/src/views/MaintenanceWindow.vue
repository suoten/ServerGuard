<template>
  <div class="mw-page">
    <!-- 标题栏 -->
    <div class="page-header">
      <div class="header-left">
        <h2>变更窗口推荐</h2>
        <span class="header-sub">基于 30 天历史负载分析最佳维护时段</span>
      </div>
      <el-button :icon="Refresh" type="primary" @click="fetchRecommendation" :loading="loading">重新分析</el-button>
    </div>

    <div v-if="recommendation" class="recommendation-content">
      <!-- 推荐理由 -->
      <el-card shadow="hover" style="margin-bottom: 16px">
        <template #header>
          <div class="card-header">
            <span>
              <el-icon style="vertical-align: middle"><MagicStick /></el-icon>
              智能推荐
            </span>
            <el-tag type="info" size="small">分析范围: {{ recommendation.analysis_range }}</el-tag>
          </div>
        </template>
        <div class="reason-block">
          <p class="reason-text">{{ recommendation.reason }}</p>
          <div class="reason-meta">
            <el-tag size="small">采样点: {{ recommendation.total_samples }}</el-tag>
            <el-tag size="small" type="info">生成时间: {{ formatTime(recommendation.timestamp) }}</el-tag>
          </div>
        </div>
      </el-card>

      <!-- 推荐时段列表 -->
      <el-card shadow="hover" style="margin-bottom: 16px">
        <template #header><span>推荐变更时段 TOP {{ recommendation.best_slots?.length || 0 }}</span></template>
        <el-table :data="recommendation.best_slots || []" stripe>
          <el-table-column label="排名" width="60" type="index" />
          <el-table-column label="星期" width="80">
            <template #default="{ row }">
              <el-tag :type="dayTagType(row.day_of_week)" size="small">{{ row.day_name }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="时间段" width="120">
            <template #default="{ row }">
              {{ String(row.hour).padStart(2, '0') }}:00 - {{ String(row.hour + 1).padStart(2, '0') }}:00
            </template>
          </el-table-column>
          <el-table-column label="CPU 均值" width="100" align="right">
            <template #default="{ row }">
              <span :style="{ color: cpuColor(row.avg_cpu) }">{{ row.avg_cpu.toFixed(0) }}%</span>
            </template>
          </el-table-column>
          <el-table-column label="CPU 峰值" width="100" align="right">
            <template #default="{ row }">
              <span :style="{ color: cpuColor(row.max_cpu) }">{{ row.max_cpu.toFixed(0) }}%</span>
            </template>
          </el-table-column>
          <el-table-column label="内存均值" width="100" align="right">
            <template #default="{ row }">{{ row.avg_mem.toFixed(0) }}%</template>
          </el-table-column>
          <el-table-column label="采样数" prop="sample_count" width="80" align="right" />
          <el-table-column label="综合评分" width="120" align="right">
            <template #default="{ row }">
              <el-progress
                :percentage="Math.min(100, Math.round(row.score))"
                :color="scoreColor(row.score)"
                :stroke-width="10"
                :format="(p: number) => p.toFixed(0)"
                style="width: 80px"
              />
            </template>
          </el-table-column>
          <el-table-column label="推荐度" width="80">
            <template #default="{ row }">
              <el-rate
                :model-value="scoreToStars(row.score)"
                disabled
                size="small"
              />
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <!-- 可视化图表 -->
      <el-card v-if="recommendation.best_slots && recommendation.best_slots.length > 0" shadow="hover">
        <template #header><span>负载评分对比</span></template>
        <v-chart :option="chartOption" :autoresize="true" style="height: 300px" />
      </el-card>
    </div>

    <el-empty v-else description="点击「重新分析」生成变更窗口推荐">
      <el-button type="primary" @click="fetchRecommendation" :loading="loading">开始分析</el-button>
    </el-empty>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { ElMessage } from 'element-plus'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import { Refresh, MagicStick } from '@element-plus/icons-vue'
import { useDark } from '@/composables/useDark'

use([CanvasRenderer, BarChart, GridComponent, TooltipComponent, LegendComponent])

const { isDark } = useDark()

const recommendation = ref<any>(null)
const loading = ref(false)

async function fetchRecommendation() {
  loading.value = true
  try {
    const resp = await axios.get('/api/maintenance-window/recommend')
    recommendation.value = resp.data
  } catch (err: any) {
    ElMessage.error('获取推荐失败: ' + (err?.response?.data?.error || err.message))
  } finally {
    loading.value = false
  }
}

function dayTagType(day: number): string {
  if (day === 0 || day === 6) return 'warning'
  return ''
}

function cpuColor(cpu: number): string {
  if (cpu < 30) return '#22c55e'
  if (cpu < 60) return '#e6a23c'
  return '#f56c6c'
}

function scoreColor(score: number): string {
  if (score < 30) return '#22c55e'
  if (score < 50) return '#e6a23c'
  return '#f56c6c'
}

function scoreToStars(score: number): number {
  if (score < 20) return 5
  if (score < 35) return 4
  if (score < 50) return 3
  if (score < 70) return 2
  return 1
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

const chartOption = computed(() => {
  if (!recommendation.value?.best_slots) return {}
  const slots = recommendation.value.best_slots
  const labels = slots.map((s: any) => `${s.day_name} ${String(s.hour).padStart(2, '0')}:00`)
  const cpuAvg = slots.map((s: any) => s.avg_cpu)
  const cpuMax = slots.map((s: any) => s.max_cpu)
  const memAvg = slots.map((s: any) => s.avg_mem)
  const scores = slots.map((s: any) => s.score)

  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: {
      data: ['CPU均值', 'CPU峰值', '内存均值', '综合评分'],
      top: 0,
      textStyle: { color: isDark.value ? '#ccc' : '#333' },
    },
    grid: { top: 40, right: 20, bottom: 30, left: 50 },
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { color: isDark.value ? '#ccc' : '#333', fontSize: 11, rotate: 15 },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: isDark.value ? '#ccc' : '#333' },
      splitLine: { lineStyle: { color: isDark.value ? '#263152' : '#eee' } },
    },
    series: [
      { name: 'CPU均值', type: 'bar', data: cpuAvg, itemStyle: { color: '#4c6fff', borderRadius: [3, 3, 0, 0] } },
      { name: 'CPU峰值', type: 'bar', data: cpuMax, itemStyle: { color: '#f56c6c', borderRadius: [3, 3, 0, 0] } },
      { name: '内存均值', type: 'bar', data: memAvg, itemStyle: { color: '#e6a23c', borderRadius: [3, 3, 0, 0] } },
      { name: '综合评分', type: 'bar', data: scores, itemStyle: { color: '#22c55e', borderRadius: [3, 3, 0, 0] } },
    ],
  }
})

onMounted(() => {
  fetchRecommendation()
})
</script>

<style scoped>
.mw-page {
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
.reason-block {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.reason-text {
  font-size: 14px;
  line-height: 1.8;
  color: var(--sg-text-2);
  white-space: pre-wrap;
}
.reason-meta {
  display: flex;
  gap: 8px;
}
</style>
