<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>SSL 证书管理</span>
            <el-input v-model="searchQuery" placeholder="搜索域名/机构..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
          </div>
          <div>
            <el-tag type="info" size="small" style="margin-right: 10px">自动扫描中</el-tag>
            <el-button type="primary" @click="scanCerts" :loading="scanning">立即扫描</el-button>
          </div>
        </div>
      </template>

      <el-alert type="success" :closable="false" style="margin-bottom: 15px">
        <p style="font-size: 13px; line-height: 1.8; margin: 0">
          ServerGuard 会自动扫描本机的 HTTPS 证书。证书即将过期时会自动续期：
          如果检测到宝塔面板，优先用宝塔的 Let's Encrypt 续期（无需额外配置邮箱）；
          否则使用内置 ACME 自动续期。你不需要手动操作。
        </p>
      </el-alert>

      <!-- 汇总统计卡片 -->
      <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap">
        <div
          v-for="tab in tabs"
          :key="tab.key"
          @click="activeTab = tab.key"
          :style="{
            cursor: 'pointer',
            flex: '1 1 140px',
            minWidth: '140px',
            padding: '12px 16px',
            borderRadius: '8px',
            border: activeTab === tab.key ? `2px solid ${tab.color}` : '1px solid #e4e7ed',
            background: activeTab === tab.key ? tab.bg : '#fff',
            transition: 'all 0.2s',
            textAlign: 'center',
          }"
        >
          <div :style="{ fontSize: '24px', fontWeight: 700, color: tab.color, lineHeight: '1.2' }">
            <CountUp :value="tab.count" />
          </div>
          <div style="font-size: 12px; color: #909399; margin-top: 4px">{{ tab.label }}</div>
        </div>
      </div>

      <el-table :data="pagedCerts" v-loading="loading">
        <el-table-column prop="domain" label="域名" min-width="200" />
        <el-table-column prop="issuer" label="颁发机构" width="200" />
        <el-table-column label="到期时间" width="200">
          <template #default="{ row }">
            <div style="display: flex; flex-direction: column; gap: 2px">
              <span v-if="row.not_after" style="font-size: 12px; color: #909399">{{ formatDate(row.not_after) }}</span>
              <el-tag :type="certTagType(row.days_until_expiry)" size="small">
                {{ row.days_until_expiry > 0 ? row.days_until_expiry + ' 天后到期' : '已过期 ' + Math.abs(row.days_until_expiry) + ' 天' }}
              </el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="managed_by" label="管理方" width="100">
          <template #default="{ row }">{{ managerLabel(row.managed_by) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button size="small" type="warning" @click="renewCert(row.domain)" :disabled="row.days_until_expiry > 30">
              续期
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 30px 0">
            <p style="color: #909399; margin-bottom: 8px">暂无证书数据</p>
            <p style="color: #c0c4cc; font-size: 13px; margin-bottom: 15px">
              Agent 会自动扫描 443、8443 等端口的 HTTPS 证书
            </p>
            <el-button type="primary" size="small" @click="scanCerts" :loading="scanning">立即扫描</el-button>
          </div>
        </template>
      </el-table>
      <div v-if="filteredCerts.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredCerts.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import CountUp from '../components/CountUp.vue'

const certs = ref<any[]>([])
const loading = ref(false)
const scanning = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)
const activeTab = ref('all')
let timer: ReturnType<typeof setInterval> | null = null

const filteredCerts = computed(() => {
  let list = certs.value
  // 按标签筛选
  switch (activeTab.value) {
    case 'expired':
      list = list.filter((c: any) => c.days_until_expiry <= 0)
      break
    case '14days':
      list = list.filter((c: any) => c.days_until_expiry > 0 && c.days_until_expiry <= 14)
      break
    case '30days':
      list = list.filter((c: any) => c.days_until_expiry > 0 && c.days_until_expiry <= 30)
      break
    case 'safe':
      list = list.filter((c: any) => c.days_until_expiry > 30)
      break
  }
  // 按搜索词筛选
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter((c: any) =>
      c.domain?.toLowerCase().includes(q) ||
      c.issuer?.toLowerCase().includes(q)
    )
  }
  return list
})

const pagedCerts = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredCerts.value.slice(start, start + pageSize.value)
})

// 统计各状态数量
const stats = computed(() => {
  const all = certs.value
  return {
    total: all.length,
    expired: all.filter((c: any) => c.days_until_expiry <= 0).length,
    within14: all.filter((c: any) => c.days_until_expiry > 0 && c.days_until_expiry <= 14).length,
    within30: all.filter((c: any) => c.days_until_expiry > 0 && c.days_until_expiry <= 30).length,
    safe: all.filter((c: any) => c.days_until_expiry > 30).length,
  }
})

// 标签页配置
const tabs = computed(() => [
  { key: 'all',     label: '全部',     count: stats.value.total,    color: '#409eff', bg: '#ecf5ff' },
  { key: 'expired', label: '已过期',   count: stats.value.expired,  color: '#f56c6c', bg: '#fef0f0' },
  { key: '14days',  label: '14天内',   count: stats.value.within14, color: '#e6a23c', bg: '#fdf6ec' },
  { key: '30days',  label: '30天内',   count: stats.value.within30, color: '#e6a23c', bg: '#fdf6ec' },
  { key: 'safe',    label: '安全(>30天)', count: stats.value.safe,  color: '#67c23a', bg: '#f0f9eb' },
])

async function fetchCerts() {
  loading.value = true
  try {
    const resp = await axios.get('/api/certs')
    const raw = resp.data.certs || []
    // 前端过滤：去掉域名为空的无效记录 + 去重
    const seen = new Set()
    certs.value = raw.filter((c: any) => {
      if (!c.domain || c.domain === '-' || c.domain === '') return false
      const key = `${c.domain}:${c.port || 0}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    // 按到期时间升序排列（最紧急的在前）
    .sort((a: any, b: any) => (a.days_until_expiry || 0) - (b.days_until_expiry || 0))
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

async function scanCerts() {
  scanning.value = true
  ElMessage.info('正在扫描本机证书...')
  try {
    await axios.post('/api/certs/scan')
    await fetchCerts()
    ElMessage.success('证书扫描完成')
  } catch (err) {
    ElMessage.error('扫描失败')
  } finally {
    scanning.value = false
  }
}

async function renewCert(domain: string) {
  try {
    await ElMessageBox.confirm(
      `确认续期域名 ${domain} 的SSL证书吗？续期期间网站可能短暂受影响。`,
      '证书续期确认',
      { confirmButtonText: '续期', cancelButtonText: '取消', type: 'warning' }
    )
  } catch { return }
  ElMessage.info(`正在续期 ${domain}...`)
  try {
    await axios.post('/api/certs/renew', { domain })
    ElMessage.success(`${domain} 续期已触发`)
    await fetchCerts()
  } catch (err: any) {
    ElMessage.error('续期失败')
  }
}

function formatDate(dateStr: string): string {
  if (!dateStr) return ''
  try {
    const d = new Date(dateStr)
    return d.getFullYear() + '-' + 
      String(d.getMonth() + 1).padStart(2, '0') + '-' +
      String(d.getDate()).padStart(2, '0')
  } catch {
    return dateStr
  }
}

function certTagType(days: number) {
  if (days <= 0) return 'danger'
  if (days <= 7) return 'danger'
  if (days <= 14) return 'warning'
  if (days <= 30) return 'info'
  return 'success'
}

function managerLabel(manager: string): string {
  const labels: Record<string, string> = {
    baota: '宝塔',
    acme: '自动续期',
    manual: '手动',
  }
  return labels[manager] || manager || '-'
}

onMounted(() => {
  fetchCerts()
  timer = setInterval(fetchCerts, 60000)
})

onUnmounted(() => {
  if (timer) { clearInterval(timer); timer = null }
})
</script>
