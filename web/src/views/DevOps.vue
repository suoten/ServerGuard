<template>
  <div class="devops-page">
    <div class="page-header">
      <div class="header-left">
        <h2>DevOps 运维</h2>
        <span class="header-sub">ServerGuard 自动巡检 · 无需配置</span>
      </div>
      <div class="header-right">
        <el-button @click="refreshAll" :loading="loading" :icon="Refresh">刷新</el-button>
      </div>
    </div>

    <!-- 自动巡检概览 -->
    <el-card v-if="discovery" shadow="hover" class="overview-card">
      <div class="overview-row">
        <div class="overview-item">
          <el-icon color="#409eff"><Box /></el-icon>
          <span class="overview-label">构建目录</span>
          <strong>{{ discovery.build_dirs?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon :color="discovery.cron_conflicts?.length > 0 ? '#f56c6c' : '#67c23a'"><Timer /></el-icon>
          <span class="overview-label">Cron 冲突</span>
          <strong :class="discovery.cron_conflicts?.length > 0 ? 'text-danger' : ''">{{ discovery.cron_conflicts?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon color="#409eff"><Connection /></el-icon>
          <span class="overview-label">API 依赖</span>
          <strong>{{ discovery.api_deps?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon color="#409eff"><Files /></el-icon>
          <span class="overview-label">Git 仓库</span>
          <strong>{{ discovery.git_repos?.length || 0 }}</strong>
        </div>
      </div>
      <div class="auto-scan-info">
        <el-tag type="success" size="small" effect="plain">
          <el-icon><CircleCheck /></el-icon>
          自动巡检中
        </el-tag>
        <span class="scan-time" v-if="discovery.discovery_time">
          上次扫描: {{ formatTime(discovery.discovery_time) }}
        </span>
        <span class="scan-hint">后端每 10 分钟自动扫描 · 无需手动触发</span>
      </div>
    </el-card>

    <el-tabs v-model="activeTab" class="devops-tabs">
      <!-- 构建目录（自动发现） -->
      <el-tab-pane label="构建目录" name="build-dirs">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>构建产物自动清理 <el-tag size="small" type="success" effect="plain">自动发现</el-tag></span>
              <el-button size="small" @click="showBuildDirDialog = true">手动添加</el-button>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px" v-if="discovery?.build_dirs?.length > 0">
            自动发现 {{ discovery.build_dirs.length }} 个构建目录，大于 100MB 的已自动纳入监控和清理
          </el-alert>
          <el-table :data="pagedBuildDirs" style="width: 100%" v-loading="loading">
            <el-table-column prop="path" label="目录路径" min-width="200" show-overflow-tooltip />
            <el-table-column prop="maxSizeGB" label="阈值(GB)" width="90" />
            <el-table-column prop="keepVersions" label="保留版本" width="90" />
            <el-table-column label="上次清理" width="160">
              <template #default="{ row }">{{ row.lastCleanedAt && row.lastCleanedAt !== '0001-01-01T00:00:00Z' ? formatTime(row.lastCleanedAt) : '未执行' }}</template>
            </el-table-column>
            <el-table-column label="释放空间" width="100">
              <template #default="{ row }">{{ row.lastFreedBytes ? (row.lastFreedBytes / 1024 / 1024).toFixed(1) + 'MB' : '-' }}</template>
            </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="buildDirPage" v-model:page-size="buildDirSize" :page-sizes="[10, 20, 50, 100]" :total="buildDirs.length" layout="total, sizes, prev, pager, next" />
</div>
<!-- 自动发现的构建目录 -->
          <el-divider v-if="discovery?.build_dirs?.length > 0">自动发现的构建目录</el-divider>
          <el-table :data="discovery?.build_dirs || []" style="width: 100%" v-if="discovery?.build_dirs?.length > 0">
            <el-table-column prop="path" label="目录路径" min-width="200" show-overflow-tooltip />
            <el-table-column label="大小" width="100">
              <template #default="{ row }">
                <el-tag :type="row.size_mb > 1024 ? 'danger' : row.size_mb > 100 ? 'warning' : 'info'" size="small">
                  {{ row.size_mb > 1024 ? (row.size_mb / 1024).toFixed(1) + 'GB' : row.size_mb.toFixed(1) + 'MB' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="build_type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag size="small">{{ buildTypeLabel(row.build_type) }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!loading && (buildDirs.length === 0 && !(discovery?.build_dirs?.length > 0))" description="暂无构建目录" />
        </el-card>
      </el-tab-pane>

      <!-- Cron 冲突（自动检测） -->
      <el-tab-pane label="Cron 冲突" name="cron-conflicts">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>定时任务冲突检测 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            自动解析 /etc/crontab 和 /etc/cron.d/ 中的定时任务，检测时间重叠和资源竞争
          </el-alert>
          <template v-if="discovery?.cron_conflicts?.length > 0">
            <el-alert type="warning" :closable="false" style="margin-bottom: 12px">
              <div v-for="(conflict, i) in discovery.cron_conflicts" :key="i" style="line-height: 1.8">
                <el-icon><Warning /></el-icon> {{ conflict }}
              </div>
            </el-alert>
          </template>
          <el-empty v-else description="未检测到 cron 冲突">
            <template #description>
              <el-icon color="#67c23a"><CircleCheck /></el-icon>
              <span>定时任务无冲突，ServerGuard 已自动检测</span>
            </template>
          </el-empty>
        </el-card>
      </el-tab-pane>

      <!-- API 依赖（自动发现） -->
      <el-tab-pane label="API 依赖" name="api-deps">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>第三方 API 依赖健康度 <el-tag size="small" type="success" effect="plain">自动发现</el-tag></span>
              <div>
                <el-button size="small" @click="showAPIDepDialog = true">手动添加</el-button>
                <el-button size="small" type="primary" @click="checkAPIDeps" :loading="checkLoading">立即检查</el-button>
              </div>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px" v-if="discovery?.api_deps?.length > 0">
            从 Nginx 配置中自动发现 {{ discovery.api_deps.length }} 个 upstream API 依赖
          </el-alert>
          <el-table :data="pagedApiDeps" style="width: 100%" v-loading="loading">
            <el-table-column prop="name" label="名称" min-width="120" />
            <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
            <el-table-column label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="row.available ? 'success' : 'danger'" size="small">{{ row.available ? '正常' : '异常' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="延迟" width="80">
              <template #default="{ row }">{{ row.latency ? Math.round(row.latency / 1e6) + 'ms' : '-' }}</template>
            </el-table-column>
            <el-table-column prop="downCount" label="失败次数" width="80" />
            <el-table-column label="上次检查" width="160">
              <template #default="{ row }">{{ row.lastCheck ? formatTime(row.lastCheck) : '-' }}</template>
            </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="apiDepPage" v-model:page-size="apiDepSize" :page-sizes="[10, 20, 50, 100]" :total="apiDeps.length" layout="total, sizes, prev, pager, next" />
</div>
<!-- 自动发现的 API 依赖 -->
          <el-divider v-if="discovery?.api_deps?.length > 0">自动发现的 API 依赖（来自 Nginx 配置）</el-divider>
          <el-table :data="discovery?.api_deps || []" style="width: 100%" v-if="discovery?.api_deps?.length > 0">
            <el-table-column prop="name" label="配置文件" min-width="120" />
            <el-table-column prop="url" label="URL" min-width="250" show-overflow-tooltip />
          </el-table>
          <el-empty v-if="!loading && apiDeps.length === 0 && !(discovery?.api_deps?.length > 0)" description="暂无 API 依赖监控" />
        </el-card>
      </el-tab-pane>

      <!-- Git 仓库（自动发现） -->
      <el-tab-pane label="Git 仓库" name="git-repos">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Git 仓库自动发现 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-table :data="pagedGitRepos" style="width: 100%" v-loading="loading">
            <el-table-column prop="path" label="仓库路径" min-width="250" show-overflow-tooltip />
            <el-table-column prop="branch" label="当前分支" width="120" />
            <el-table-column prop="lastCommit" label="最新提交" min-width="100" />
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="gitRepoPage" v-model:page-size="gitRepoSize" :page-sizes="[10, 20, 50, 100]" :total="(discovery?.git_repos || []).length" layout="total, sizes, prev, pager, next" />
</div>
<el-empty v-if="!loading && !(discovery?.git_repos?.length > 0)" description="未发现 Git 仓库" />
        </el-card>
      </el-tab-pane>

      <!-- 部署记录（保留） -->
      <el-tab-pane label="部署记录" name="deployments">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Git Webhook 部署历史</span>
              <el-button type="primary" size="small" @click="showDeployDialog = true">手动触发部署</el-button>
            </div>
          </template>
          <el-table :data="pagedDeployments" style="width: 100%" v-loading="loading">
            <el-table-column prop="repo" label="仓库" min-width="120" />
            <el-table-column prop="branch" label="分支" width="100" />
            <el-table-column prop="commit" label="提交" width="100" show-overflow-tooltip />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="deployStatusType(row.status)" size="small">{{ deployStatusLabel(row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="startedAt" label="开始时间" width="160">
              <template #default="{ row }">{{ formatTime(row.startedAt) }}</template>
            </el-table-column>
            <el-table-column label="耗时" width="80">
              <template #default="{ row }">
                {{ row.finishedAt ? Math.round((new Date(row.finishedAt).getTime() - new Date(row.startedAt).getTime()) / 1000) + 's' : '-' }}
              </template>
            </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="deployPage" v-model:page-size="deploySize" :page-sizes="[10, 20, 50, 100]" :total="deployments.length" layout="total, sizes, prev, pager, next" />
</div>
<el-empty v-if="!loading && deployments.length === 0" description="暂无部署记录" />
        </el-card>
      </el-tab-pane>

      <!-- 批处理作业（保留） -->
      <el-tab-pane label="批处理作业" name="batch-jobs">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>批处理作业守护 (ETL/数据同步)</span>
              <el-button size="small" type="primary" @click="showBatchDialog = true">添加作业</el-button>
            </div>
          </template>
          <el-table :data="pagedBatchJobs" style="width: 100%">
            <el-table-column prop="name" label="作业名称" min-width="120" />
            <el-table-column prop="schedule" label="调度" width="100" />
            <el-table-column prop="lastStatus" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="batchStatusType(row.lastStatus)" size="small">{{ row.lastStatus || '-' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="retryCount" label="重试" width="60" />
            <el-table-column label="上次执行" width="160">
              <template #default="{ row }">{{ row.lastRun ? formatTime(row.lastRun) : '-' }}</template>
            </el-table-column>
            <el-table-column label="耗时" width="80">
              <template #default="{ row }">{{ row.lastDuration ? Math.round(row.lastDuration / 1e9) + 's' : '-' }}</template>
            </el-table-column>
          </el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="batchPage" v-model:page-size="batchSize" :page-sizes="[10, 20, 50, 100]" :total="batchJobs.length" layout="total, sizes, prev, pager, next" />
</div>
        </el-card>
      </el-tab-pane>

      <!-- 文件传输（保留） -->
      <el-tab-pane label="文件传输" name="transfers">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>文件传输守护 (SFTP/RSYNC)</span>
              <el-button size="small" @click="showTransferDialog = true">添加监控</el-button>
            </div>
          </template>
          <el-table :data="pagedTransfers" style="width: 100%">
            <el-table-column prop="name" label="名称" min-width="120" />
            <el-table-column prop="watchDir" label="监控目录" min-width="150" />
            <el-table-column prop="expectedFile" label="期望文件" min-width="120" />
            <el-table-column label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="transferStatusType(row.status)" size="small">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="上次发现" width="160">
              <template #default="{ row }">{{ row.lastSeen ? formatTime(row.lastSeen) : '-' }}</template>
            </el-table-column>
          </el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="transferPage" v-model:page-size="transferSize" :page-sizes="[10, 20, 50, 100]" :total="transfers.length" layout="total, sizes, prev, pager, next" />
</div>
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 部署对话框 -->
    <el-dialog v-model="showDeployDialog" title="手动触发部署" width="500px">
      <el-form label-width="80px">
        <el-form-item label="仓库"><el-input v-model="deployForm.repo" placeholder="user/repo" /></el-form-item>
        <el-form-item label="分支"><el-input v-model="deployForm.branch" placeholder="main" /></el-form-item>
        <el-form-item label="提交"><el-input v-model="deployForm.commit" placeholder="abc123" /></el-form-item>
        <el-form-item label="脚本"><el-input v-model="deployForm.deploy_script" type="textarea" :rows="3" placeholder="/opt/deploy.sh" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDeployDialog = false">取消</el-button>
        <el-button type="primary" @click="triggerDeploy" :loading="deploying">部署</el-button>
      </template>
    </el-dialog>

    <!-- 构建目录对话框 -->
    <el-dialog v-model="showBuildDirDialog" title="添加构建目录监控" width="450px">
      <el-form label-width="100px">
        <el-form-item label="目录路径"><el-input v-model="buildDirForm.path" placeholder="/opt/app/builds" /></el-form-item>
        <el-form-item label="阈值(GB)"><el-input-number v-model="buildDirForm.maxSizeGB" :min="1" :max="100" /></el-form-item>
        <el-form-item label="保留版本"><el-input-number v-model="buildDirForm.keepVersions" :min="1" :max="50" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showBuildDirDialog = false">取消</el-button>
        <el-button type="primary" @click="addBuildDir">添加</el-button>
      </template>
    </el-dialog>

    <!-- 批处理作业对话框 -->
    <el-dialog v-model="showBatchDialog" title="添加批处理作业" width="500px">
      <el-form label-width="80px">
        <el-form-item label="名称"><el-input v-model="batchForm.name" placeholder="ETL数据同步" /></el-form-item>
        <el-form-item label="命令"><el-input v-model="batchForm.command" type="textarea" :rows="2" placeholder="/opt/sync.sh" /></el-form-item>
        <el-form-item label="最大重试"><el-input-number v-model="batchForm.maxRetries" :min="1" :max="10" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showBatchDialog = false">取消</el-button>
        <el-button type="primary" @click="addBatchJob">添加</el-button>
      </template>
    </el-dialog>

    <!-- API依赖对话框 -->
    <el-dialog v-model="showAPIDepDialog" title="添加 API 依赖监控" width="500px">
      <el-form label-width="80px">
        <el-form-item label="名称"><el-input v-model="apiDepForm.name" placeholder="支付接口" /></el-form-item>
        <el-form-item label="URL"><el-input v-model="apiDepForm.url" placeholder="https://api.example.com/health" /></el-form-item>
        <el-form-item label="方法">
          <el-select v-model="apiDepForm.method" style="width: 100px">
            <el-option label="GET" value="GET" />
            <el-option label="POST" value="POST" />
            <el-option label="HEAD" value="HEAD" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAPIDepDialog = false">取消</el-button>
        <el-button type="primary" @click="addAPIDep">添加</el-button>
      </template>
    </el-dialog>

    <!-- 文件传输对话框 -->
    <el-dialog v-model="showTransferDialog" title="添加文件传输监控" width="500px">
      <el-form label-width="100px">
        <el-form-item label="名称"><el-input v-model="transferForm.name" placeholder="上游文件到达" /></el-form-item>
        <el-form-item label="监控目录"><el-input v-model="transferForm.watchDir" placeholder="/data/incoming" /></el-form-item>
        <el-form-item label="文件模式"><el-input v-model="transferForm.expectedFile" placeholder="*.csv" /></el-form-item>
        <el-form-item label="超时(分钟)"><el-input-number v-model="transferForm.timeoutMin" :min="1" :max="1440" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showTransferDialog = false">取消</el-button>
        <el-button type="primary" @click="addTransfer">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { Refresh, Box, Timer, Connection, Files, CircleCheck, Warning } from '@element-plus/icons-vue'
import dayjs from 'dayjs'

const loading = ref(false)
const checkLoading = ref(false)
const activeTab = ref('build-dirs')
const deploying = ref(false)

// 自动发现数据
const discovery = ref<any>(null)

// 数据
const deployments = ref<any[]>([])
const buildDirs = ref<any[]>([])
const batchJobs = ref<any[]>([])
const apiDeps = ref<any[]>([])
const transfers = ref<any[]>([])

// 分页状态
const buildDirPage = ref(1)
const buildDirSize = ref(10)
const deployPage = ref(1)
const deploySize = ref(10)
const apiDepPage = ref(1)
const apiDepSize = ref(10)
const gitRepoPage = ref(1)
const gitRepoSize = ref(10)
const batchPage = ref(1)
const batchSize = ref(10)
const transferPage = ref(1)
const transferSize = ref(10)

const pagedBuildDirs = computed(() => { const s = (buildDirPage.value - 1) * buildDirSize.value; return buildDirs.value.slice(s, s + buildDirSize.value) })
const pagedDeployments = computed(() => { const s = (deployPage.value - 1) * deploySize.value; return deployments.value.slice(s, s + deploySize.value) })
const pagedApiDeps = computed(() => { const s = (apiDepPage.value - 1) * apiDepSize.value; return apiDeps.value.slice(s, s + apiDepSize.value) })
const pagedGitRepos = computed(() => { const s = (gitRepoPage.value - 1) * gitRepoSize.value; return (discovery.value?.git_repos || []).slice(s, s + gitRepoSize.value) })
const pagedBatchJobs = computed(() => { const s = (batchPage.value - 1) * batchSize.value; return batchJobs.value.slice(s, s + batchSize.value) })
const pagedTransfers = computed(() => { const s = (transferPage.value - 1) * transferSize.value; return transfers.value.slice(s, s + transferSize.value) })

// 对话框
const showDeployDialog = ref(false)
const showBuildDirDialog = ref(false)
const showBatchDialog = ref(false)
const showAPIDepDialog = ref(false)
const showTransferDialog = ref(false)

// 表单
const deployForm = ref({ repo: '', branch: '', commit: '', deploy_script: '' })
const buildDirForm = ref({ path: '', maxSizeGB: 5, keepVersions: 10 })
const batchForm = ref({ name: '', command: '', maxRetries: 3 })
const apiDepForm = ref({ name: '', url: '', method: 'GET' })
const transferForm = ref({ name: '', watchDir: '', expectedFile: '', timeoutMin: 30 })

// 自动发现
async function fetchDiscovery() {
  try {
    const r = await axios.get('/api/devops/auto-discover')
    discovery.value = r.data
  } catch { /* 静默 */ }
}

async function fetchDeployments() {
  try { const r = await axios.get('/api/devops/deployments'); deployments.value = r.data.deployments || [] } catch { /* 静默 */ }
}
async function fetchBuildDirs() {
  try { const r = await axios.get('/api/devops/build-dirs'); buildDirs.value = r.data.dirs || [] } catch { /* 静默 */ }
}
async function fetchBatchJobs() {
  try { const r = await axios.get('/api/devops/batch-jobs'); batchJobs.value = r.data.jobs || [] } catch { /* 静默 */ }
}
async function fetchAPIDeps() {
  try { const r = await axios.get('/api/devops/api-deps'); apiDeps.value = r.data.deps || [] } catch { /* 静默 */ }
}
async function fetchTransfers() {
  try { const r = await axios.get('/api/devops/transfers'); transfers.value = r.data.watches || [] } catch { /* 静默 */ }
}

async function refreshAll() {
  loading.value = true
  await Promise.all([fetchDiscovery(), fetchDeployments(), fetchBuildDirs(), fetchBatchJobs(), fetchAPIDeps(), fetchTransfers()])
  loading.value = false
}

async function triggerDeploy() {
  deploying.value = true
  try {
    await axios.post('/api/devops/deploy', deployForm.value)
    ElMessage.success('部署已触发')
    showDeployDialog.value = false
    await fetchDeployments()
  } catch (err: any) {
    ElMessage.error('部署失败: ' + (err?.response?.data?.error || err.message))
  } finally { deploying.value = false }
}

async function addBuildDir() {
  try {
    await axios.post('/api/devops/build-dirs', buildDirForm.value)
    ElMessage.success('构建目录已添加')
    showBuildDirDialog.value = false
    await fetchBuildDirs()
  } catch { ElMessage.error('添加失败') }
}

async function checkBuildDirs() {
  checkLoading.value = true
  try {
    await axios.post('/api/devops/build-dirs/check')
    ElMessage.success('清理检查完成')
    await fetchBuildDirs()
  } catch { ElMessage.error('检查失败') }
  finally { checkLoading.value = false }
}

async function addBatchJob() {
  try {
    await axios.post('/api/devops/batch-jobs', batchForm.value)
    ElMessage.success('作业已添加')
    showBatchDialog.value = false
    await fetchBatchJobs()
  } catch { ElMessage.error('添加失败') }
}

async function addAPIDep() {
  try {
    await axios.post('/api/devops/api-deps', apiDepForm.value)
    ElMessage.success('API 依赖已添加')
    showAPIDepDialog.value = false
    await fetchAPIDeps()
  } catch { ElMessage.error('添加失败') }
}

async function checkAPIDeps() {
  checkLoading.value = true
  try {
    await axios.post('/api/devops/api-deps/check')
    ElMessage.success('检查完成')
    await fetchAPIDeps()
  } catch { ElMessage.error('检查失败') }
  finally { checkLoading.value = false }
}

async function addTransfer() {
  try {
    const w = { ...transferForm.value, timeout: transferForm.value.timeoutMin * 60 * 1e9 }
    await axios.post('/api/devops/transfers', w)
    ElMessage.success('监控已添加')
    showTransferDialog.value = false
    await fetchTransfers()
  } catch { ElMessage.error('添加失败') }
}

function deployStatusType(s: string) { return s === 'success' ? 'success' : s === 'rolled_back' ? 'warning' : 'danger' }
function deployStatusLabel(s: string) { return { success: '成功', failed: '失败', rolled_back: '已回滚', running: '运行中' }[s] || s }
function batchStatusType(s: string) { return s === 'success' ? 'success' : s === 'failed' ? 'danger' : 'warning' }
function transferStatusType(s: string) { return s === 'ok' ? 'success' : s === 'timeout' ? 'danger' : 'warning' }
function formatTime(ts: string) { return ts ? dayjs(ts).format('MM-DD HH:mm') : '-' }
function buildTypeLabel(t: string) {
  const labels: Record<string, string> = {
    npm: 'Node.js (npm)',
    maven: 'Java (Maven)',
    gradle: 'Java (Gradle)',
    frontend: '前端构建',
    nextjs: 'Next.js',
    nuxt: 'Nuxt.js',
    svelte: 'SvelteKit',
    nitro: 'Nitro',
    'java-out': 'Java 输出',
    go: 'Go',
    rust: 'Rust (Cargo)',
    python: 'Python',
    composer: 'PHP (Composer)',
    dotnet: '.NET',
    cmake: 'C/C++ (CMake)',
    make: 'Make',
    webpack: 'Webpack',
    vite: 'Vite',
    bin: '二进制',
    out: '输出',
    build: '构建',
    unknown: '未知'
  }
  return labels[t] || t || '未知'
}

onMounted(() => { refreshAll() })
</script>

<style scoped>
.devops-page { max-width: 1400px; margin: 0 auto; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left h2 { font-size: 20px; margin: 0; }
.header-sub { font-size: 13px; color: var(--sg-text-3); margin-left: 8px; }
.devops-tabs { min-height: 400px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }

.overview-card { margin-bottom: 16px; }
.overview-row { display: flex; gap: 32px; flex-wrap: wrap; }
.overview-item { display: flex; align-items: center; gap: 8px; }
.overview-item .overview-label { font-size: 14px; color: var(--sg-text-3); }
.overview-item strong { font-size: 20px; }
.text-danger { color: #f56c6c; }
.auto-scan-info { margin-top: 12px; display: flex; align-items: center; gap: 12px; font-size: 12px; color: var(--sg-text-3); }
.scan-time { color: var(--sg-text-3); }
.scan-hint { color: var(--sg-text-3); }
</style>
