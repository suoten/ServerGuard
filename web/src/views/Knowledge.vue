<template>
  <div class="knowledge-page">
    <!-- 标题栏 -->
    <div class="page-header">
      <div class="header-left">
        <h2>故障知识库</h2>
        <span class="header-sub">症状指纹匹配 · 历史方案检索</span>
      </div>
      <el-button-group>
        <el-button :icon="Search" @click="searchDialogVisible = true">搜索相似故障</el-button>
        <el-button :icon="Refresh" @click="fetchData" :loading="loading">刷新</el-button>
      </el-button-group>
    </div>

    <!-- 统计卡片 -->
    <el-row :gutter="16" v-if="stats" style="margin-bottom: 16px">
      <el-col :xs="12" :sm="8">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" style="color: #4c6fff"><Document /></el-icon>
            <div>
              <div class="stat-num">{{ stats.total_entries || 0 }}</div>
              <div class="stat-name">知识条目总数</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="8">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" style="color: #e6a23c"><Warning /></el-icon>
            <div>
              <div class="stat-num">{{ stats.recurring_issues || 0 }}</div>
              <div class="stat-name">反复出现问题</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <el-icon class="stat-icon" style="color: #22c55e"><Histogram /></el-icon>
            <div>
              <div class="stat-num">{{ Object.keys(stats.by_source || {}).length }}</div>
              <div class="stat-name">来源模块数</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 来源分布 -->
    <el-card v-if="stats && stats.by_source" shadow="hover" style="margin-bottom: 16px">
      <template #header><span>按来源模块分布</span></template>
      <div class="source-distribution">
        <div v-for="(count, source) in stats.by_source" :key="source" class="source-bar">
          <span class="source-name">{{ source || '未知' }}</span>
          <el-progress
            :percentage="Math.round((count as number) / (stats.total_entries || 1) * 100)"
            :format="() => `${count}`"
            :stroke-width="16"
            style="flex: 1; margin: 0 12px"
          />
        </div>
      </div>
    </el-card>

    <!-- 知识条目列表 -->
    <el-card shadow="hover">
      <template #header>
        <div class="card-header">
          <span>知识条目列表</span>
          <el-pagination
            v-if="total > pageSize"
            small
            layout="prev, pager, next"
            :total="total"
            :page-size="pageSize"
            v-model:current-page="currentPage"
            @current-change="fetchEntries"
          />
        </div>
      </template>

      <el-table :data="entries" v-loading="loading" stripe>
        <el-table-column label="症状" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="symptom-text">{{ row.symptom }}</span>
          </template>
        </el-table-column>
        <el-table-column label="来源" width="100">
          <template #default="{ row }">
            <el-tag size="small" type="info">{{ row.source || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="严重度" width="80">
          <template #default="{ row }">
            <el-tag :type="severityTagType(row.severity)" size="small">{{ row.severity || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="修复动作" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="action-text">{{ row.action || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结果" width="80">
          <template #default="{ row }">
            <el-tag :type="row.action_result === 'success' ? 'success' : row.action_result === 'failed' ? 'danger' : 'info'" size="small">
              {{ row.action_result || '-' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="出现次数" width="80" align="right">
          <template #default="{ row }">
            <el-badge :value="row.occurrence_count" :type="row.occurrence_count > 3 ? 'danger' : 'warning'" />
          </template>
        </el-table-column>
        <el-table-column label="最近出现" width="140">
          <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="{ row }">
            <el-button text size="small" @click="showDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && entries.length === 0" description="知识库暂无条目，自动修复时将自动记录" />
    </el-card>

    <!-- 搜索对话框 -->
    <el-dialog v-model="searchDialogVisible" title="搜索相似故障" width="500px">
      <el-form label-position="top">
        <el-form-item label="故障症状">
          <el-input v-model="searchSymptom" placeholder="输入故障症状关键词，如：CPU 使用率过高" clearable />
        </el-form-item>
        <el-form-item label="来源模块（可选）">
          <el-input v-model="searchSource" placeholder="如：resource、log、security" clearable />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="searchDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="doSearch" :loading="searching">搜索</el-button>
      </template>
    </el-dialog>

    <!-- 搜索结果对话框 -->
    <el-dialog v-model="resultDialogVisible" title="相似故障检索结果" width="700px">
      <div v-if="searchResults.length > 0">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          找到 {{ searchResults.length }} 条相似故障记录
        </el-alert>
        <div v-for="(r, i) in searchResults" :key="i" class="search-result-item">
          <div class="result-header">
            <el-tag :type="severityTagType(r.severity)" size="small">{{ r.severity }}</el-tag>
            <span class="result-symptom">{{ r.symptom }}</span>
            <el-tag v-if="r.occurrence_count > 1" type="danger" size="small">出现 {{ r.occurrence_count }} 次</el-tag>
          </div>
          <div class="result-detail">
            <p v-if="r.root_cause"><strong>根因：</strong>{{ r.root_cause }}</p>
            <p v-if="r.action"><strong>修复动作：</strong>{{ r.action }}</p>
            <p v-if="r.effect"><strong>效果：</strong>{{ r.effect }}</p>
            <p class="result-time">最近出现：{{ formatTime(r.last_seen) }}</p>
          </div>
        </div>
      </div>
      <el-empty v-else description="未找到相似故障记录" />
    </el-dialog>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailDialogVisible" title="知识条目详情" width="600px">
      <template v-if="detailEntry">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="症状">{{ detailEntry.symptom }}</el-descriptions-item>
          <el-descriptions-item label="来源">{{ detailEntry.source || '-' }}</el-descriptions-item>
          <el-descriptions-item label="严重度">{{ detailEntry.severity || '-' }}</el-descriptions-item>
          <el-descriptions-item label="根因分析">{{ detailEntry.root_cause || '-' }}</el-descriptions-item>
          <el-descriptions-item label="修复动作">{{ detailEntry.action || '-' }}</el-descriptions-item>
          <el-descriptions-item label="修复结果">{{ detailEntry.action_result || '-' }}</el-descriptions-item>
          <el-descriptions-item label="效果描述">{{ detailEntry.effect || '-' }}</el-descriptions-item>
          <el-descriptions-item label="出现次数">{{ detailEntry.occurrence_count }}</el-descriptions-item>
          <el-descriptions-item label="首次出现">{{ formatTime(detailEntry.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="最近出现">{{ formatTime(detailEntry.last_seen) }}</el-descriptions-item>
          <el-descriptions-item label="解决时间">{{ detailEntry.resolved_at ? formatTime(detailEntry.resolved_at) : '-' }}</el-descriptions-item>
        </el-descriptions>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { Search, Refresh, Document, Warning, Histogram } from '@element-plus/icons-vue'

const loading = ref(false)
const entries = ref<any[]>([])
const stats = ref<any>(null)
const total = ref(0)
const pageSize = 50
const currentPage = ref(1)

const searchDialogVisible = ref(false)
const searchSymptom = ref('')
const searchSource = ref('')
const searching = ref(false)
const searchResults = ref<any[]>([])
const resultDialogVisible = ref(false)

const detailDialogVisible = ref(false)
const detailEntry = ref<any>(null)

async function fetchEntries() {
  loading.value = true
  try {
    const offset = (currentPage.value - 1) * pageSize
    const resp = await axios.get(`/api/knowledge?limit=${pageSize}&offset=${offset}`)
    entries.value = resp.data.entries || []
    if (entries.value.length > 0) {
      total.value = entries.value.length >= pageSize ? (currentPage.value + 1) * pageSize : currentPage.value * pageSize
    }
  } catch {
    entries.value = []
  } finally {
    loading.value = false
  }
}

async function fetchStats() {
  try {
    const resp = await axios.get('/api/knowledge/stats')
    stats.value = resp.data
  } catch { /* 静默 */ }
}

async function fetchData() {
  await Promise.all([fetchEntries(), fetchStats()])
}

async function doSearch() {
  if (!searchSymptom.value.trim()) return
  searching.value = true
  try {
    const params: Record<string, string> = { symptom: searchSymptom.value }
    if (searchSource.value) params.source = searchSource.value
    const resp = await axios.get('/api/knowledge/search', { params })
    searchResults.value = resp.data.entries || []
    searchDialogVisible.value = false
    resultDialogVisible.value = true
  } catch {
    searchResults.value = []
  } finally {
    searching.value = false
  }
}

function showDetail(row: any) {
  detailEntry.value = row
  detailDialogVisible.value = true
}

function severityTagType(sev: string): string {
  switch (sev) {
    case 'critical': case 'fatal': return 'danger'
    case 'warning': case 'high': return 'warning'
    case 'info': case 'low': return 'info'
    default: return 'info'
  }
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm')
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.knowledge-page {
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
.stat-card {
  transition: all 0.25s;
}
.stat-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
}
.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}
.stat-icon {
  font-size: 36px;
}
.stat-num {
  font-size: 26px;
  font-weight: 700;
  color: var(--sg-text-1);
  font-variant-numeric: tabular-nums;
}
.stat-name {
  font-size: 13px;
  color: var(--sg-text-3);
}
.source-distribution {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.source-bar {
  display: flex;
  align-items: center;
}
.source-name {
  min-width: 100px;
  font-size: 13px;
  font-weight: 500;
  color: var(--sg-text-2);
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.symptom-text {
  font-weight: 500;
  color: var(--sg-text-1);
}
.action-text {
  font-size: 13px;
  color: var(--sg-text-2);
}
.search-result-item {
  padding: 12px;
  border: 1px solid var(--sg-border);
  border-radius: 8px;
  margin-bottom: 12px;
  transition: box-shadow 0.25s;
}
.search-result-item:hover {
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.06);
}
.result-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.result-symptom {
  font-weight: 600;
  color: var(--sg-text-1);
  flex: 1;
}
.result-detail p {
  font-size: 13px;
  color: var(--sg-text-2);
  line-height: 1.6;
  margin: 4px 0;
}
.result-time {
  color: var(--sg-text-3) !important;
  font-size: 12px !important;
}
</style>
