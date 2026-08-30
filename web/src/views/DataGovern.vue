<template>
  <div class="datagovern-page">
    <div class="page-header">
      <div class="header-left">
        <h2>数据治理</h2>
        <span class="header-sub">ServerGuard 自动巡检 · 无需配置</span>
      </div>
      <el-button @click="refreshAll" :loading="loading" :icon="Refresh">刷新</el-button>
    </div>

    <!-- 自动发现概览 -->
    <el-card v-if="discovery" shadow="hover" class="overview-card">
      <div class="overview-row">
        <div class="overview-item">
          <el-icon color="#f56c6c"><Coin /></el-icon>
          <span class="overview-label">MySQL 实例</span>
          <strong>{{ discovery.mysql_instances?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon color="#67c23a"><Key /></el-icon>
          <span class="overview-label">Redis 实例</span>
          <strong>{{ discovery.redis_instances?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon color="#409eff"><Files /></el-icon>
          <span class="overview-label">备份文件</span>
          <strong>{{ discovery.backup_files?.length || 0 }}</strong>
        </div>
        <div class="overview-item">
          <el-icon color="#e6a23c"><Document /></el-icon>
          <span class="overview-label">备份任务</span>
          <strong>{{ discovery.backup_tasks?.length || 0 }}</strong>
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
        <span class="scan-hint">后端每 10 分钟自动发现数据库和缓存 · 每天凌晨 2-3 点自动备份 · 无需手动配置</span>
      </div>
    </el-card>

    <el-tabs v-model="activeTab" class="dg-tabs">
      <!-- 数据库自动发现 -->
      <el-tab-pane label="数据库发现" name="discovery">
        <!-- MySQL 自动发现 -->
        <el-card style="margin-bottom: 16px">
          <template #header>
            <div class="card-header">
              <span>MySQL 自动发现 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px" v-if="discovery?.mysql_instances?.length > 0">
            自动发现 {{ discovery.mysql_instances.length }} 个 MySQL 实例，已自动注册备份任务（每天凌晨 2 点）
          </el-alert>
          <el-table :data="discovery?.mysql_instances || []" style="width: 100%" v-loading="loading">
            <el-table-column label="端口" width="80">
              <template #default="{ row }"><el-tag size="small">{{ row.port }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="socket" label="Socket" min-width="200" show-overflow-tooltip />
            <el-table-column prop="version" label="版本" min-width="200" show-overflow-tooltip />
            <el-table-column label="备份任务" width="120">
              <template #default="{ row }">
                <el-tag v-if="discovery?.backup_tasks?.some((t: any) => t.id === `auto-mysql-${row.port}`)" type="success" size="small">已自动注册</el-tag>
                <el-tag v-else type="info" size="small">待注册</el-tag>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-if="!loading && !(discovery?.mysql_instances?.length > 0)" description="未发现 MySQL 实例" />
        </el-card>

        <!-- Redis 自动发现 -->
        <el-card>
          <template #header>
            <div class="card-header">
              <span>Redis 自动发现 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-table :data="discovery?.redis_instances || []" style="width: 100%" v-loading="loading">
            <el-table-column prop="addr" label="地址" min-width="150" />
            <el-table-column prop="version" label="版本" min-width="150" />
          </el-table>
          <el-empty v-if="!loading && !(discovery?.redis_instances?.length > 0)" description="未发现 Redis 实例" />
        </el-card>
      </el-tab-pane>

      <!-- 备份管理 -->
      <el-tab-pane label="备份管理" name="backups">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>数据库自动备份 <el-tag size="small" type="success" effect="plain">自动调度</el-tag></span>
              <el-button size="small" type="primary" @click="showBackupDialog = true">手动添加</el-button>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            ServerGuard 自动发现 MySQL 实例后自动注册备份任务 · 每天凌晨 2 点自动执行 · 保留最近 7 份 · 自动验证备份完整性
          </el-alert>
          <el-table :data="(backupTasks.slice((backupPage-1)*backupSize, backupPage*backupSize))" style="width: 100%" v-loading="loading">
            <el-table-column prop="name" label="任务名" min-width="120" />
            <el-table-column prop="dbType" label="类型" width="80" />
            <el-table-column prop="database" label="数据库" width="100" />
            <el-table-column prop="schedule" label="调度" width="100" />
            <el-table-column prop="runCount" label="成功次数" width="90" />
            <el-table-column label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="row.lastStatus === 'success' ? 'success' : 'danger'" size="small">{{ row.lastStatus || '-' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="上次备份" width="160">
              <template #default="{ row }">{{ row.lastRun ? formatTime(row.lastRun) : '未执行' }}</template>
            </el-table-column>
            <el-table-column label="大小" width="80">
              <template #default="{ row }">{{ row.lastSize ? (row.lastSize / 1024 / 1024).toFixed(1) + 'MB' : '-' }}</template>
            </el-table-column>
            <el-table-column label="操作" width="80">
              <template #default="{ row }">
                <el-button size="small" type="primary" link @click="runBackup(row.id)">执行</el-button>
              </template>
            </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="backupPage" v-model:page-size="backupSize" :page-sizes="[10, 20, 50, 100]" :total="backupTasks.length" layout="total, sizes, prev, pager, next" />
</div>
<el-empty v-if="!loading && backupTasks.length === 0" description="暂无备份任务，ServerGuard 将自动发现并注册" />
        </el-card>

        <!-- 备份文件 -->
        <el-card style="margin-top: 16px" v-if="backupFiles.length > 0">
          <template #header><span>备份文件</span></template>
          <el-table :data="backupFiles" style="width: 100%">
            <el-table-column prop="name" label="文件名" min-width="200" />
            <el-table-column label="大小" width="80">
              <template #default="{ row }">{{ (row.size / 1024 / 1024).toFixed(1) }}MB</template>
            </el-table-column>
            <el-table-column label="时间" width="160">
              <template #default="{ row }">{{ formatTime(row.mod_time) }}</template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-tab-pane>

      <!-- 死锁与连接池 -->
      <el-tab-pane label="死锁/连接池" name="deadlocks">
        <el-card style="margin-bottom: 16px">
          <template #header>
            <div class="card-header">
              <span>数据库死锁自动猎杀 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
              <el-button size="small" type="warning" @click="huntDeadlocks" :loading="scanLoading">立即猎杀</el-button>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            ServerGuard 自动发现 MySQL 后自动巡检死锁 · 自动 Kill 运行超过 60s 的非关键会话
          </el-alert>
          <el-table :data="deadlockRecords" style="width: 100%">
            <el-table-column label="时间" width="160"><template #default="{ row }">{{ formatTime(row.timestamp) }}</template></el-table-column>
            <el-table-column prop="action" label="动作" width="80" />
            <el-table-column prop="victimSQL" label="SQL" min-width="200" show-overflow-tooltip />
          </el-table>
          <el-empty v-if="!scanLoading && deadlockRecords.length === 0" description="无死锁记录，自动巡检中" />
        </el-card>

        <el-card>
          <template #header>
            <div class="card-header">
              <span>连接池泄漏诊断 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-descriptions :column="3" border v-if="connPoolDiag">
            <el-descriptions-item label="连接数">{{ connPoolDiag.threadsConnected }}</el-descriptions-item>
            <el-descriptions-item label="最大连接">{{ connPoolDiag.maxConnections }}</el-descriptions-item>
            <el-descriptions-item label="使用率">
              <el-tag :type="connPoolDiag.usagePercent > 80 ? 'danger' : 'success'">{{ connPoolDiag.usagePercent.toFixed(1) }}%</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="是否泄漏">
              <el-tag :type="connPoolDiag.isLeaking ? 'danger' : 'success'">{{ connPoolDiag.isLeaking ? '是' : '否' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="建议" :span="2">{{ connPoolDiag.suggestion }}</el-descriptions-item>
          </el-descriptions>
          <el-empty v-else description="连接池诊断结果将在自动巡检后显示" />
        </el-card>
      </el-tab-pane>

      <!-- 缓存与时序DB -->
      <el-tab-pane label="缓存/时序" name="cache">
        <el-card style="margin-bottom: 16px">
          <template #header>
            <div class="card-header">
              <span>缓存雪崩预防器 (Redis TTL 分析) <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
              <el-button size="small" type="warning" @click="checkCache" :loading="scanLoading">立即分析</el-button>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            自动发现 Redis 后自动分析 TTL 分布 · 检测同时过期风险
          </el-alert>
          <el-descriptions :column="3" border v-if="cacheAnalysis">
            <el-descriptions-item label="扫描Key数">{{ cacheAnalysis.totalKeysScanned }}</el-descriptions-item>
            <el-descriptions-item label="雪崩风险Key数">
              <el-tag :type="cacheAnalysis.spillRiskKeys > 0 ? 'danger' : 'success'">{{ cacheAnalysis.spillRiskKeys }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
          <el-table :data="cacheAnalysis?.clusters || []" style="width: 100%; margin-top: 12px">
            <el-table-column label="TTL区间" min-width="120">
              <template #default="{ row }">{{ row.ttlStart }}s - {{ row.ttlEnd }}s</template>
            </el-table-column>
            <el-table-column prop="keyCount" label="Key数量" width="100" />
            <el-table-column label="风险" width="80">
              <template #default="{ row }"><el-tag :type="row.spillRisk ? 'danger' : 'success'" size="small">{{ row.spillRisk ? '高风险' : '正常' }}</el-tag></template>
            </el-table-column>
          </el-table>
        </el-card>

        <el-card>
          <template #header>
            <div class="card-header">
              <span>时序数据库异常检测 (InfluxDB)</span>
              <el-button size="small" type="warning" @click="checkTSDB" :loading="scanLoading">立即检测</el-button>
            </div>
          </template>
          <el-empty v-if="tsdbAnomalies.length === 0" description="未发现异常" />
          <el-table :data="tsdbAnomalies" style="width: 100%">
            <el-table-column prop="type" label="类型" width="150" />
            <el-table-column label="数值" width="100"><template #default="{ row }">{{ row.value.toFixed(0) }}</template></el-table-column>
            <el-table-column label="阈值" width="100"><template #default="{ row }">{{ row.threshold.toFixed(0) }}</template></el-table-column>
            <el-table-column prop="suggestion" label="建议" min-width="200" show-overflow-tooltip />
          </el-table>
        </el-card>
      </el-tab-pane>

      <!-- 备份校验与大表归档 -->
      <el-tab-pane label="校验/归档" name="verify">
        <el-card style="margin-bottom: 16px">
          <template #header>
            <div class="card-header">
              <span>备份完整性校验 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
              <el-button size="small" type="primary" @click="verifyBackup" :loading="scanLoading">立即校验</el-button>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            每次备份后自动验证 gzip 完整性和表结构
          </el-alert>
          <el-descriptions :column="2" border v-if="verifyResult">
            <el-descriptions-item label="备份文件">{{ verifyResult.backupFile }}</el-descriptions-item>
            <el-descriptions-item label="是否通过">
              <el-tag :type="verifyResult.verified ? 'success' : 'danger'">{{ verifyResult.verified ? '通过' : '失败' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="表数量">{{ verifyResult.tableCount }}</el-descriptions-item>
            <el-descriptions-item label="错误">{{ verifyResult.error || '无' }}</el-descriptions-item>
          </el-descriptions>
        </el-card>

        <el-card style="margin-bottom: 16px">
          <template #header>
            <div class="card-header">
              <span>大表预警 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
            </div>
          </template>
          <el-alert type="info" :closable="false" style="margin-bottom: 12px">
            自动发现 MySQL 后自动检查超过 1GB 的大表并生成归档建议
          </el-alert>
          <el-table :data="bigTables" style="width: 100%; margin-top: 12px">
            <el-table-column prop="database" label="数据库" width="100" />
            <el-table-column prop="tableName" label="表名" min-width="120" />
            <el-table-column label="大小" width="80"><template #default="{ row }">{{ row.sizeMB.toFixed(0) }}MB</template></el-table-column>
            <el-table-column prop="rowsCount" label="行数" width="80" />
          </el-table>
          <el-empty v-if="!scanLoading && bigTables.length === 0" description="无大表预警，自动巡检中" />
        </el-card>

        <el-card>
          <template #header><span>数据库归档（手动执行）</span></template>
          <el-form label-width="80px" style="margin-bottom: 12px">
            <el-form-item label="DSN"><el-input v-model="archiveForm.dsn" placeholder="root:password@tcp(127.0.0.1:3306)/" /></el-form-item>
            <el-form-item label="数据库"><el-input v-model="archiveForm.database" placeholder="mydb" /></el-form-item>
            <el-form-item label="表名"><el-input v-model="archiveForm.table" placeholder="orders" /></el-form-item>
            <el-form-item label="日期列"><el-input v-model="archiveForm.dateColumn" placeholder="create_time" /></el-form-item>
            <el-form-item label="归档日期"><el-input v-model="archiveForm.beforeDate" placeholder="2024-01-01" /></el-form-item>
          </el-form>
          <el-button size="small" type="primary" @click="archiveTable" :loading="scanLoading">执行归档</el-button>
        </el-card>
      </el-tab-pane>

      <!-- 敏感数据扫描 -->
      <el-tab-pane label="敏感数据" name="sensitive">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>敏感数据泄露扫描 <el-tag size="small" type="success" effect="plain">自动巡检</el-tag></span>
              <el-button size="small" type="danger" @click="scanSensitive" :loading="scanLoading">立即扫描</el-button>
            </div>
          </template>
          <el-alert type="warning" :closable="false" style="margin-bottom: 12px">
            自动扫描 /var/log、/etc、/www/wwwroot 等目录中的手机号、身份证、API Key、密码等敏感信息
          </el-alert>
          <el-table :data="sensitiveFindings" style="width: 100%">
            <el-table-column label="类型" width="80">
              <template #default="{ row }">
                <el-tag :type="sensitiveTypeColor(row.type)" size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="filePath" label="文件路径" min-width="200" show-overflow-tooltip />
            <el-table-column prop="lineNum" label="行号" width="60" />
            <el-table-column prop="match" label="匹配内容" min-width="150" />
          </el-table>
          <el-empty v-if="!scanLoading && sensitiveFindings.length === 0" description="未发现敏感数据，自动巡检中" />
        </el-card>
      </el-tab-pane>
    </el-tabs>

    <!-- 备份任务对话框 -->
    <el-dialog v-model="showBackupDialog" title="添加备份任务" width="500px">
      <el-form label-width="100px">
        <el-form-item label="任务名"><el-input v-model="backupForm.name" placeholder="MySQL备份" /></el-form-item>
        <el-form-item label="类型">
          <el-select v-model="backupForm.dbType" style="width: 120px">
            <el-option label="MySQL" value="mysql" />
            <el-option label="PostgreSQL" value="postgresql" />
          </el-select>
        </el-form-item>
        <el-form-item label="DSN"><el-input v-model="backupForm.dsn" placeholder="root:password@tcp(127.0.0.1:3306)/" /></el-form-item>
        <el-form-item label="数据库"><el-input v-model="backupForm.database" placeholder="mydb" /></el-form-item>
        <el-form-item label="调度"><el-input v-model="backupForm.schedule" placeholder="0 2 * * *" /></el-form-item>
        <el-form-item label="保留份数"><el-input-number v-model="backupForm.maxBackups" :min="1" :max="30" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showBackupDialog = false">取消</el-button>
        <el-button type="primary" @click="addBackupTask">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { Refresh, Coin, Key, Files, Document, CircleCheck } from '@element-plus/icons-vue'
import dayjs from 'dayjs'

const loading = ref(false)
const scanLoading = ref(false)
const activeTab = ref('discovery')

// 自动发现数据
const discovery = ref<any>(null)

const backupTasks = ref<any[]>([])
const backupFiles = ref<any[]>([])
const sensitiveFindings = ref<any[]>([])

// 分页状态
const backupPage = ref(1)
const backupSize = ref(10)
const deadlockRecords = ref<any[]>([])
const connPoolDiag = ref<any>(null)
const cacheAnalysis = ref<any>(null)
const tsdbAnomalies = ref<any[]>([])
const verifyResult = ref<any>(null)
const bigTables = ref<any[]>([])

const showBackupDialog = ref(false)
const backupForm = ref({ id: '', name: '', dbType: 'mysql', dsn: '', database: '', schedule: '0 2 * * *', uploadOSS: false, ossBucket: '', maxBackups: 7 })
const archiveForm = ref({ dsn: '', database: '', table: '', dateColumn: 'create_time', beforeDate: '2024-01-01' })

async function fetchDiscovery() {
  try {
    const r = await axios.get('/api/datagovern/auto-discover')
    discovery.value = r.data
    // 自动发现的备份任务也同步到本地列表
    if (r.data.backup_tasks) {
      // 合并自动发现的备份任务
      const autoTasks = r.data.backup_tasks
      for (const t of autoTasks) {
        if (!backupTasks.value.some((existing: any) => existing.id === t.id)) {
          backupTasks.value.push(t)
        }
      }
    }
  } catch { /* 静默 */ }
}

async function fetchAutoCheck() {
  try {
    const r = await axios.get('/api/datagovern/auto-check')
    const data = r.data
    if (data.conn_pool_status) connPoolDiag.value = data.conn_pool_status
    if (data.deadlock_records) deadlockRecords.value = data.deadlock_records
    if (data.big_tables) bigTables.value = data.big_tables
    if (data.cache_analysis) cacheAnalysis.value = data.cache_analysis
  } catch { /* 静默 */ }
}

async function refreshAll() {
  loading.value = true
  try {
    const r = await axios.get('/api/datagovern/backups')
    backupTasks.value = r.data.tasks || []
    backupFiles.value = r.data.files || []
  } catch { /* 静默 */ }
  await fetchDiscovery()
  await fetchAutoCheck()
  loading.value = false
}

async function runBackup(id: string) {
  scanLoading.value = true
  try {
    await axios.post(`/api/datagovern/backups/${id}/run`)
    ElMessage.success('备份已触发')
    await refreshAll()
  } catch (e: any) { ElMessage.error('备份失败: ' + (e?.response?.data?.error || '')) }
  finally { scanLoading.value = false }
}

async function addBackupTask() {
  try {
    await axios.post('/api/datagovern/backups', backupForm.value)
    ElMessage.success('备份任务已添加')
    showBackupDialog.value = false
    await refreshAll()
  } catch { ElMessage.error('添加失败') }
}

async function scanSensitive() {
  scanLoading.value = true
  try {
    const r = await axios.post('/api/datagovern/sensitive-scan')
    sensitiveFindings.value = r.data.findings || []
    ElMessage.success(`扫描完成，发现 ${sensitiveFindings.value.length} 处泄露`)
  } catch { ElMessage.error('扫描失败') }
  finally { scanLoading.value = false }
}

async function huntDeadlocks() {
  scanLoading.value = true
  try {
    // 使用自动发现的 DSN
    const port = discovery.value?.mysql_instances?.[0]?.port || 3306
    const r = await axios.post('/api/datagovern/deadlocks', null, { params: { port } })
    deadlockRecords.value = r.data.records || []
    ElMessage.success(`猎杀完成，处理 ${deadlockRecords.value.length} 条记录`)
  } catch { ElMessage.error('猎杀失败，需要 MySQL 端口') }
  finally { scanLoading.value = false }
}

async function checkCache() {
  scanLoading.value = true
  try {
    const r = await axios.post('/api/datagovern/cache-avalanche')
    cacheAnalysis.value = r.data.analysis
  } catch { ElMessage.error('分析失败') }
  finally { scanLoading.value = false }
}

async function checkTSDB() {
  scanLoading.value = true
  try {
    const r = await axios.post('/api/datagovern/tsdb-anomaly')
    tsdbAnomalies.value = r.data.anomalies || []
  } catch { ElMessage.error('检测失败') }
  finally { scanLoading.value = false }
}

async function verifyBackup() {
  scanLoading.value = true
  try {
    const r = await axios.post('/api/datagovern/verify-backup')
    verifyResult.value = r.data.result
  } catch { ElMessage.error('校验失败') }
  finally { scanLoading.value = false }
}

async function checkBigTables() {
  scanLoading.value = true
  try {
    const port = discovery.value?.mysql_instances?.[0]?.port || 3306
    const r = await axios.post('/api/datagovern/big-tables', null, { params: { port } })
    bigTables.value = r.data.alerts || []
  } catch { ElMessage.error('检查失败') }
  finally { scanLoading.value = false }
}

async function archiveTable() {
  scanLoading.value = true
  try {
    await axios.post('/api/datagovern/archive', archiveForm.value)
    ElMessage.success('归档已触发')
  } catch (e: any) { ElMessage.error('归档失败: ' + (e?.response?.data?.error || '')) }
  finally { scanLoading.value = false }
}

function sensitiveTypeColor(t: string) { return { phone: 'warning', idcard: 'danger', apikey: 'danger', password: 'danger' }[t] || 'info' }
function formatTime(ts: string) { return ts ? dayjs(ts).format('MM-DD HH:mm') : '-' }

onMounted(() => { refreshAll() })
</script>

<style scoped>
.datagovern-page { max-width: 1400px; margin: 0 auto; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.header-left h2 { font-size: 20px; margin: 0; }
.header-sub { font-size: 13px; color: var(--sg-text-3); margin-left: 8px; }
.dg-tabs { min-height: 400px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }

.overview-card { margin-bottom: 16px; }
.overview-row { display: flex; gap: 32px; flex-wrap: wrap; }
.overview-item { display: flex; align-items: center; gap: 8px; }
.overview-item .overview-label { font-size: 14px; color: var(--sg-text-3); }
.overview-item strong { font-size: 20px; }
.auto-scan-info { margin-top: 12px; display: flex; align-items: center; gap: 12px; font-size: 12px; color: var(--sg-text-3); }
.scan-time { color: var(--sg-text-3); }
.scan-hint { color: var(--sg-text-3); }
</style>
