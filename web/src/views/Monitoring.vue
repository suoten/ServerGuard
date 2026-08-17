<template>
  <div>
    <el-tabs v-model="activeTab">
      <!-- 网站存活性监控 -->
      <el-tab-pane label="网站存活性监控" name="sites">
        <!-- 自动发现区域 -->
        <el-card style="margin-bottom: 16px">
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span>自动发现站点 <el-tag v-if="discoverSource" size="small" type="info">{{ discoverSource }}</el-tag></span>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-input v-model="discoveredSearch" placeholder="搜索站点..." size="small" clearable style="width: 150px" :prefix-icon="Search" />
                <el-button size="small" @click="discoverSites" :loading="discovering">扫描服务器</el-button>
                <el-button type="primary" size="small" @click="batchImport" :disabled="discoveredSites.length === 0" v-if="discoveredSites.length > 0">
                  一键导入 ({{ selectedCount }})
                </el-button>
              </div>
            </div>
          </template>

          <div v-if="discovering" style="text-align: center; padding: 20px">
            <el-text type="info">正在扫描 Nginx / Apache / IIS / 宝塔 配置...</el-text>
          </div>

          <div v-else-if="discoveredSites.length > 0">
            <el-checkbox-group v-model="selectedUrls">
              <el-table :data="pagedDiscoveredSites" style="width: 100%" size="small">
                <el-table-column width="50">
                  <template #default="scope">
                    <el-checkbox :value="scope.row.url" :disabled="scope.row.already_monitored">
                      <span v-if="scope.row.already_monitored" style="color: #67c23a; font-size: 12px">已监控</span>
                    </el-checkbox>
                  </template>
                </el-table-column>
                <el-table-column prop="name" label="站点名称" width="180" />
                <el-table-column prop="url" label="URL" show-overflow-tooltip />
                <el-table-column label="来源" width="100">
                  <template #default="scope">
                    <el-tag size="small" :type="sourceTagType(scope.row.source)">{{ sourceLabel(scope.row.source) }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="SSL" width="60">
                  <template #default="scope">
                    <el-tag v-if="scope.row.ssl" size="small" type="success">HTTPS</el-tag>
                    <el-tag v-else size="small" type="info">HTTP</el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="port" label="端口" width="70" />
              </el-table>
              <div v-if="filteredDiscoveredSites.length > 10" style="margin-top: 10px; display: flex; justify-content: flex-end">
                <el-pagination
                  v-model:current-page="discoveredPage"
                  v-model:page-size="discoveredPageSize"
                  :page-sizes="[10, 20, 50, 100]"
                  :total="filteredDiscoveredSites.length"
                  layout="total, sizes, prev, pager, next"
                  size="small"
                />
              </div>
            </el-checkbox-group>
            <div style="margin-top: 10px">
              <el-button size="small" @click="selectAll">全选</el-button>
              <el-button size="small" @click="selectedUrls = []">取消全选</el-button>
            </div>
          </div>

          <div v-else style="text-align: center; padding: 20px">
            <el-text type="info">点击"扫描服务器"自动发现已配置的网站，或手动添加</el-text>
          </div>
        </el-card>

        <!-- 已监控列表 -->
        <el-card>
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span>监控列表 ({{ filteredSites.length }})</span>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-input v-model="sitesSearch" placeholder="搜索名称/URL..." size="small" clearable style="width: 180px" :prefix-icon="Search" />
                <el-button size="small" type="danger" :disabled="selectedSites.length === 0" @click="batchDeleteSites">批量删除({{ selectedSites.length }})</el-button>
                <el-button type="primary" size="small" @click="showAddSite = true">手动添加</el-button>
              </div>
            </div>
          </template>
          <el-table :data="pagedSites" v-loading="loading" style="width: 100%" @selection-change="handleSitesSelectionChange">
            <el-table-column type="selection" width="45" />
            <el-table-column label="状态" width="80">
              <template #default="scope">
                <span class="status-light" :class="siteLightClass(scope.row)"></span>
              </template>
            </el-table-column>
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="url" label="URL" show-overflow-tooltip />
            <el-table-column label="状态码" width="80">
              <template #default="scope">{{ scope.row.status_code || '-' }}</template>
            </el-table-column>
            <el-table-column label="延迟" width="100">
              <template #default="scope">
                <span v-if="scope.row.up">{{ (scope.row.latency / 1000000).toFixed(0) }}ms</span>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column label="检查" width="110">
              <template #default="scope">
                <span style="font-size: 12px">{{ scope.row.total_checks }}次 (失败{{ scope.row.failed_checks }})</span>
              </template>
            </el-table-column>
            <el-table-column label="最后检查" width="170">
              <template #default="scope">{{ formatTime(scope.row.last_check) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="80">
              <template #default="scope">
                <el-button type="danger" size="small" text @click="deleteSite(scope.row.id)">删除</el-button>
              </template>
            </el-table-column>
            <template #empty>
              <p style="color: #909399; padding: 20px 0">暂无监控，点击上方"扫描服务器"自动发现</p>
            </template>
          </el-table>
          <div v-if="filteredSites.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="sitesPage"
              v-model:page-size="sitesPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="filteredSites.length"
              layout="total, sizes, prev, pager, next"
            />
          </div>
        </el-card>
      </el-tab-pane>

      <!-- API 接口监控 -->
      <el-tab-pane label="API 接口监控" name="endpoints">
        <el-card>
          <template #header>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span>接口列表 ({{ filteredEndpoints.length }})</span>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-input v-model="endpointsSearch" placeholder="搜索名称/URL..." size="small" clearable style="width: 180px" :prefix-icon="Search" />
                <el-button size="small" type="danger" :disabled="selectedEndpoints.length === 0" @click="batchDeleteEndpoints">批量删除({{ selectedEndpoints.length }})</el-button>
                <el-button type="primary" size="small" @click="showAddEndpoint = true">添加接口</el-button>
              </div>
            </div>
          </template>
          <el-table :data="pagedEndpoints" v-loading="loading" style="width: 100%" @selection-change="handleEndpointsSelectionChange">
            <el-table-column type="selection" width="45" />
            <el-table-column prop="name" label="名称" width="150" />
            <el-table-column prop="method" label="方法" width="80">
              <template #default="scope">
                <el-tag size="small">{{ scope.row.method }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="url" label="URL" show-overflow-tooltip />
            <el-table-column label="状态码" width="80">
              <template #default="scope">
                <el-tag :type="statusCodeType(scope.row.status_code)" size="small">{{ scope.row.status_code || '-' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="P50" width="80">
              <template #default="scope">{{ scope.row.p50_ms ? scope.row.p50_ms.toFixed(0) + 'ms' : '-' }}</template>
            </el-table-column>
            <el-table-column label="P95" width="80">
              <template #default="scope">
                <span :style="{ color: p95Color(scope.row.p95_ms) }">{{ scope.row.p95_ms ? scope.row.p95_ms.toFixed(0) + 'ms' : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="P99" width="80">
              <template #default="scope">
                <span :style="{ color: p99Color(scope.row.p99_ms) }">{{ scope.row.p99_ms ? scope.row.p99_ms.toFixed(0) + 'ms' : '-' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="错误率" width="120">
              <template #default="scope">
                <el-progress :percentage="scope.row.error_rate || 0" :color="errorRateColor(scope.row.error_rate || 0)" :stroke-width="6" :show-text="false" style="width: 70px; display: inline-block;" />
                <span style="margin-left: 5px; font-size: 12px;">{{ (scope.row.error_rate || 0).toFixed(1) }}%</span>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="80">
              <template #default="scope">
                <el-button type="danger" size="small" text @click="deleteEndpoint(scope.row.id)">删除</el-button>
              </template>
            </el-table-column>
            <template #empty>
              <p style="color: #909399; padding: 20px 0">暂无接口监控，点击"添加接口"开始</p>
            </template>
          </el-table>
          <div v-if="filteredEndpoints.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="endpointsPage"
              v-model:page-size="endpointsPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="filteredEndpoints.length"
              layout="total, sizes, prev, pager, next"
            />
          </div>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 手动添加网站 -->
    <el-dialog v-model="showAddSite" title="手动添加网站监控" width="500px">
      <el-form label-width="80px">
        <el-form-item label="名称">
          <el-input v-model="newSite.name" placeholder="我的网站" />
        </el-form-item>
        <el-form-item label="URL">
          <el-input v-model="newSite.url" placeholder="https://example.com" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddSite = false">取消</el-button>
        <el-button type="primary" @click="addSite" :loading="adding">添加</el-button>
      </template>
    </el-dialog>

    <!-- 添加API接口 -->
    <el-dialog v-model="showAddEndpoint" title="添加 API 接口监控" width="500px">
      <el-form label-width="80px">
        <el-form-item label="名称">
          <el-input v-model="newEndpoint.name" placeholder="用户登录接口" />
        </el-form-item>
        <el-form-item label="方法">
          <el-select v-model="newEndpoint.method" style="width: 100px">
            <el-option label="GET" value="GET" />
            <el-option label="POST" value="POST" />
            <el-option label="PUT" value="PUT" />
            <el-option label="DELETE" value="DELETE" />
          </el-select>
        </el-form-item>
        <el-form-item label="URL">
          <el-input v-model="newEndpoint.url" placeholder="https://api.example.com/v1/login" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddEndpoint = false">取消</el-button>
        <el-button type="primary" @click="addEndpoint" :loading="adding">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import dayjs from 'dayjs'
import { Search } from '@element-plus/icons-vue'

const activeTab = ref('sites')
const loading = ref(false)
const adding = ref(false)
const sites = ref<any[]>([])
const endpoints = ref<any[]>([])
const showAddSite = ref(false)
const showAddEndpoint = ref(false)
const newSite = ref({ name: '', url: '' })
const newEndpoint = ref({ name: '', method: 'GET', url: '' })
const sitesPage = ref(1)
const sitesPageSize = ref(10)
const endpointsPage = ref(1)
const endpointsPageSize = ref(10)
const sitesSearch = ref('')
const endpointsSearch = ref('')
const discoveredSearch = ref('')
let timer: ReturnType<typeof setInterval> | null = null

const filteredSites = computed(() => {
  if (!sitesSearch.value) return sites.value
  const q = sitesSearch.value.toLowerCase()
  return sites.value.filter((s: any) => s.name?.toLowerCase().includes(q) || s.url?.toLowerCase().includes(q))
})
const pagedSites = computed(() => {
  const start = (sitesPage.value - 1) * sitesPageSize.value
  return filteredSites.value.slice(start, start + sitesPageSize.value)
})

const filteredEndpoints = computed(() => {
  if (!endpointsSearch.value) return endpoints.value
  const q = endpointsSearch.value.toLowerCase()
  return endpoints.value.filter((e: any) => e.name?.toLowerCase().includes(q) || e.url?.toLowerCase().includes(q))
})
const pagedEndpoints = computed(() => {
const start = (endpointsPage.value - 1) * endpointsPageSize.value
return filteredEndpoints.value.slice(start, start + endpointsPageSize.value)
})

const filteredDiscoveredSites = computed(() => {
  if (!discoveredSearch.value) return discoveredSites.value
  const q = discoveredSearch.value.toLowerCase()
  return discoveredSites.value.filter((s: any) => s.name?.toLowerCase().includes(q) || s.url?.toLowerCase().includes(q))
})
const pagedDiscoveredSites = computed(() => {
const start = (discoveredPage.value - 1) * discoveredPageSize.value
return filteredDiscoveredSites.value.slice(start, start + discoveredPageSize.value)
})

// Discovery state
const discovering = ref(false)
const discoveredSites = ref<any[]>([])
const discoveredPage = ref(1)
const discoveredPageSize = ref(10)
const selectedUrls = ref<string[]>([])
const discoverSource = ref('')

const selectedCount = computed(() => selectedUrls.value.length)

async function discoverSites() {
  discovering.value = true
  try {
    const resp = await axios.get('/api/probe/discover')
    discoveredSites.value = resp.data.sites || []
    discoverSource.value = resp.data.source || ''
    selectedUrls.value = discoveredSites.value
      .filter((s: any) => !s.already_monitored)
      .map((s: any) => s.url)
    if (discoveredSites.value.length > 0) {
      ElMessage.success(resp.data.message || `发现 ${discoveredSites.value.length} 个站点`)
    } else {
      ElMessage.info('未发现已配置的网站，请手动添加')
    }
  } catch (err) {
    ElMessage.error('扫描失败')
  } finally {
    discovering.value = false
  }
}

function selectAll() {
  // 全选当前搜索结果中的未监控站点
  selectedUrls.value = filteredDiscoveredSites.value
    .filter((s: any) => !s.already_monitored)
    .map((s: any) => s.url)
}

async function batchImport() {
  if (selectedUrls.value.length === 0) {
    ElMessage.warning('请至少选择一个站点')
    return
  }
  adding.value = true
  try {
    const sitesToImport = discoveredSites.value
      .filter((s: any) => selectedUrls.value.includes(s.url))
      .map((s: any) => ({ name: s.name, url: s.url }))
    const resp = await axios.post('/api/probe/discover/import', { sites: sitesToImport })
    ElMessage.success(resp.data.message || '导入成功')
    discoveredSites.value = []
    selectedUrls.value = []
    fetchData()
  } catch (err) {
    ElMessage.error('导入失败')
  } finally {
    adding.value = false
  }
}

async function fetchDiscoveredSites() {
  try {
    const resp = await axios.get('/api/probe/discover/auto')
    discoveredSites.value = resp.data.sites || []
    discoverSource.value = resp.data.source || ''
    selectedUrls.value = discoveredSites.value
      .filter((s: any) => !s.already_monitored)
      .map((s: any) => s.url)
  } catch (err) {
    // 静默失败 — 非关键功能
  }
}

async function fetchData() {
  loading.value = true
  try {
    const [sitesResp, endpointsResp] = await Promise.all([
      axios.get('/api/probe/sites'),
      axios.get('/api/probe/endpoints'),
    ])
    sites.value = sitesResp.data.sites || []
    endpoints.value = endpointsResp.data.endpoints || []
  } catch (err) {
    console.error('Failed to fetch probe data:', err)
  } finally {
    loading.value = false
  }
}

async function addSite() {
  if (!newSite.value.url) { ElMessage.warning('URL 不能为空'); return }
  adding.value = true
  try {
    await axios.post('/api/probe/sites', newSite.value)
    ElMessage.success('监控已添加')
    showAddSite.value = false
    newSite.value = { name: '', url: '' }
    fetchData()
  } catch (err) {
    ElMessage.error('添加失败')
  } finally {
    adding.value = false
  }
}

const selectedSites = ref<any[]>([])

function handleSitesSelectionChange(val: any[]) {
  selectedSites.value = val
}

async function batchDeleteSites() {
  if (selectedSites.value.length === 0) return
  try {
    await ElMessageBox.confirm(`确定删除选中的 ${selectedSites.value.length} 个监控？`, '批量删除', { type: 'warning' })
    for (const s of selectedSites.value) {
      await axios.delete(`/api/probe/sites/${s.id}`)
    }
    ElMessage.success(`已删除 ${selectedSites.value.length} 个监控`)
    selectedSites.value = []
    fetchData()
  } catch {}
}

async function deleteSite(id: string) {
  try {
    await ElMessageBox.confirm('确定删除此监控？', '确认', { type: 'warning' })
    await axios.delete(`/api/probe/sites/${id}`)
    ElMessage.success('已删除')
    fetchData()
  } catch {}
}

async function addEndpoint() {
  if (!newEndpoint.value.url) { ElMessage.warning('URL 不能为空'); return }
  adding.value = true
  try {
    await axios.post('/api/probe/endpoints', newEndpoint.value)
    ElMessage.success('接口监控已添加')
    showAddEndpoint.value = false
    newEndpoint.value = { name: '', method: 'GET', url: '' }
    fetchData()
  } catch (err) {
    ElMessage.error('添加失败')
  } finally {
    adding.value = false
  }
}

const selectedEndpoints = ref<any[]>([])

function handleEndpointsSelectionChange(val: any[]) {
  selectedEndpoints.value = val
}

async function batchDeleteEndpoints() {
  if (selectedEndpoints.value.length === 0) return
  try {
    await ElMessageBox.confirm(`确定删除选中的 ${selectedEndpoints.value.length} 个接口监控？`, '批量删除', { type: 'warning' })
    for (const e of selectedEndpoints.value) {
      await axios.delete(`/api/probe/endpoints/${e.id}`)
    }
    ElMessage.success(`已删除 ${selectedEndpoints.value.length} 个接口监控`)
    selectedEndpoints.value = []
    fetchData()
  } catch {}
}

async function deleteEndpoint(id: string) {
  try {
    await ElMessageBox.confirm('确定删除此接口监控？', '确认', { type: 'warning' })
    await axios.delete(`/api/probe/endpoints/${id}`)
    ElMessage.success('已删除')
    fetchData()
  } catch {}
}

function siteLightClass(s: any) {
  if (s.total_checks === 0) return 'gray'
  return s.up ? 'green' : 'red'
}

function sourceLabel(src: string) {
  const labels: Record<string, string> = { nginx: 'Nginx', apache: 'Apache', iis: 'IIS', baota: '宝塔' }
  return labels[src] || src
}

function sourceTagType(src: string) {
  const types: Record<string, string> = { nginx: 'success', apache: 'warning', iis: 'info', baota: 'primary' }
  return types[src] || 'info'
}

function statusCodeType(code: number) {
  if (!code) return 'info'
  if (code >= 200 && code < 300) return 'success'
  if (code >= 300 && code < 400) return 'info'
  if (code >= 400 && code < 500) return 'warning'
  return 'danger'
}

function p95Color(ms: number) {
  if (!ms) return '#909399'
  if (ms > 2000) return '#f56c6c'
  if (ms > 1000) return '#e6a23c'
  return '#67c23a'
}

function p99Color(ms: number) {
  if (!ms) return '#909399'
  if (ms > 5000) return '#f56c6c'
  if (ms > 2000) return '#e6a23c'
  return '#67c23a'
}

function errorRateColor(rate: number) {
  if (rate > 10) return '#f56c6c'
  if (rate > 5) return '#e6a23c'
  return '#67c23a'
}

function formatTime(ts: string) {
  if (!ts || ts === '0001-01-01T00:00:00Z') return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

onMounted(() => {
  fetchData()
  fetchDiscoveredSites()  // 自动加载已缓存的站点发现结果
  timer = setInterval(fetchData, 5000)
})

onUnmounted(() => {
  if (timer) { clearInterval(timer); timer = null }
})
</script>

<style scoped>
.status-light {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  display: inline-block;
}
.status-light.green { background: #67c23a; box-shadow: 0 0 6px #67c23a; }
.status-light.red { background: #f56c6c; box-shadow: 0 0 6px #f56c6c; animation: pulse 1.5s infinite; }
.status-light.gray { background: #c0c4cc; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
</style>
