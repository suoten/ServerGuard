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

      <el-table :data="pagedCerts" v-loading="loading">
        <el-table-column prop="domain" label="域名" min-width="200" />
        <el-table-column prop="issuer" label="颁发机构" width="200" />
        <el-table-column label="到期时间" width="180">
          <template #default="{ row }">
            <el-tag :type="certTagType(row.days_until_expiry)">
              {{ row.days_until_expiry > 0 ? row.days_until_expiry + ' 天后到期' : '已过期' }}
            </el-tag>
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

const certs = ref<any[]>([])
const loading = ref(false)
const scanning = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)
let timer: ReturnType<typeof setInterval> | null = null

const filteredCerts = computed(() => {
  if (!searchQuery.value) return certs.value
  const q = searchQuery.value.toLowerCase()
  return certs.value.filter((c: any) =>
    c.domain?.toLowerCase().includes(q) ||
    c.issuer?.toLowerCase().includes(q)
  )
})

const pagedCerts = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredCerts.value.slice(start, start + pageSize.value)
})

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

function certTagType(days: number) {
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
