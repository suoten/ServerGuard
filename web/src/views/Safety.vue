<template>
  <div>
    <el-alert type="info" :closable="false" style="margin-bottom: 20px">
      <template #title>什么是安全控制？</template>
      <p style="font-size: 13px; line-height: 1.8; margin: 0">
        ServerGuard 在自动修复问题时会执行一些操作（如关闭异常进程、重启服务）。
        安全控制就是给这些操作加上"刹车"——防止 Agent 误操作搞坏服务器。
        下面的"操作记录"会显示 Agent 做了什么、为什么做、结果如何。
      </p>
    </el-alert>

    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header><span>运行状态</span></template>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="当前状态">
              <el-tag :type="modeTagType">{{ modeLabel }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="自动修复">
              <el-tag v-if="safety.emergency_stop" type="danger">已暂停（紧急停止）</el-tag>
              <el-tag v-else type="success">运行中</el-tag>
            </el-descriptions-item>
          </el-descriptions>
          <div style="margin-top: 16px">
            <el-button v-if="!safety.emergency_stop" type="danger" @click="emergencyStop">
              紧急停止所有自动修复
            </el-button>
            <el-button v-else type="success" @click="emergencyResume">
              恢复自动修复
            </el-button>
          </div>
          <p style="margin-top: 10px; color: #909399; font-size: 12px">
            紧急停止 = Agent 不再执行任何修复操作，只监控和告警。遇到异常情况时可手动触发。
          </p>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header><span>进程关闭次数限制</span></template>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="本小时已关闭 / 上限">
              {{ kb.hourly_used || 0 }} / {{ kb.hourly_limit || 5 }}
            </el-descriptions-item>
            <el-descriptions-item label="今日已关闭 / 上限">
              {{ kb.daily_used || 0 }} / {{ kb.daily_limit || 20 }}
            </el-descriptions-item>
            <el-descriptions-item label="上次关闭时间">
              {{ kb.last_kill_time && kb.last_kill_time !== '0001-01-01T00:00:00Z' ? formatTime(kb.last_kill_time) : '暂无' }}
            </el-descriptions-item>
            <el-descriptions-item label="是否允许继续关闭">
              <el-tag :type="kb.can_kill ? 'success' : 'danger'">{{ kb.can_kill ? '允许' : '已达上限，暂停关闭' }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
          <p style="margin-top: 10px; color: #909399; font-size: 12px">
            防止 Agent 短时间内关闭太多进程导致服务不可用。到达上限后自动停止关闭操作。
          </p>
        </el-card>
      </el-col>
    </el-row>

    <!-- 维护窗口 -->
    <el-card style="margin-top: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>
            维护窗口
            <el-tag v-if="maintenanceActive" type="warning" size="small" style="margin-left: 8px">维护中 · 自动修复已暂停</el-tag>
          </span>
          <el-button type="primary" size="small" @click="openMaintenanceDialog">新建维护窗口</el-button>
        </div>
      </template>
      <p style="color: #909399; font-size: 13px; margin-bottom: 12px; line-height: 1.7">
        做系统升级、迁移、服务重启等变更时，先开一个维护窗口——窗口期内 ServerGuard 只监控告警、不执行任何自动修复，到期自动恢复，避免"你刚停服务它又拉起来"。
      </p>
      <el-empty v-if="maintenanceWindows.length === 0" description="暂无维护窗口" :image-size="60" />
      <el-table v-else :data="maintenanceWindows" size="small" style="width: 100%">
        <el-table-column label="窗口名称" min-width="140">
          <template #default="{ row }">
            <span style="font-weight: 600">{{ row.name }}</span>
            <el-tag v-if="isWindowActive(row)" type="warning" size="small" effect="dark" style="margin-left: 6px">进行中</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="160">
          <template #default="{ row }">{{ formatTime(row.start) }}</template>
        </el-table-column>
        <el-table-column label="结束时间" width="160">
          <template #default="{ row }">{{ formatTime(row.end) }}</template>
        </el-table-column>
        <el-table-column label="原因" min-width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.reason || '-' }}</template>
        </el-table-column>
        <el-table-column label="创建人" width="100">
          <template #default="{ row }">{{ row.created_by || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80" fixed="right">
          <template #default="{ row }">
            <el-button text type="danger" size="small" @click="deleteMaintenance(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 新建维护窗口对话框 -->
    <el-dialog v-model="maintenanceDialogVisible" title="新建维护窗口" width="480px">
      <el-form label-width="90px">
        <el-form-item label="窗口名称" required>
          <el-input v-model="maintenanceForm.name" placeholder="如：MySQL 升级迁移" maxlength="50" />
        </el-form-item>
        <el-form-item label="维护原因">
          <el-input v-model="maintenanceForm.reason" type="textarea" :rows="2" placeholder="可选，记录本次维护内容" maxlength="200" />
        </el-form-item>
        <el-form-item label="开始时间" required>
          <el-date-picker v-model="maintenanceForm.start" type="datetime" placeholder="选择开始时间" style="width: 100%" />
        </el-form-item>
        <el-form-item label="结束时间" required>
          <el-date-picker v-model="maintenanceForm.end" type="datetime" placeholder="选择结束时间" style="width: 100%" />
        </el-form-item>
        <el-form-item label="快捷选择">
          <el-button size="small" @click="quickWindow(1)">从现在起 1 小时</el-button>
          <el-button size="small" @click="quickWindow(2)">2 小时</el-button>
          <el-button size="small" @click="quickWindow(4)">4 小时</el-button>
        </el-form-item>
      </el-form>
      <el-alert type="info" :closable="false" show-icon>
        窗口期内所有自动修复动作（关闭进程/重启服务/清理/封禁）暂停，监控与告警照常。
      </el-alert>
      <template #footer>
        <el-button @click="maintenanceDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="maintenanceSaving" @click="createMaintenance">创建窗口</el-button>
      </template>
    </el-dialog>

    <!-- 操作记录 -->
    <el-card style="margin-top: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>操作记录（最近 24 小时）</span>
          <el-button text @click="fetchSafety">刷新</el-button>
        </div>
      </template>
      <p v-if="!recentActions || recentActions.length === 0" style="color: #909399; padding: 20px 0; text-align: center">
        Agent 尚未执行过任何操作。当 Agent 自动修复问题时（如关闭异常进程、重启服务），会在此显示详细记录。
      </p>
      <el-table v-else :data="pagedActions" style="width: 100%" size="small">
        <el-table-column label="时间" width="160">
          <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">{{ actionLabel(row.action?.type) }}</template>
        </el-table-column>
        <el-table-column label="操作对象" width="150">
          <template #default="{ row }">{{ row.action?.params?.name || row.action?.params?.target || row.target || '-' }}</template>
        </el-table-column>
        <el-table-column label="结果" width="80">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'" size="small">
              {{ row.success ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="详情" show-overflow-tooltip>
          <template #default="{ row }">{{ row.message || row.error || '-' }}</template>
        </el-table-column>
      </el-table>
      <div v-if="recentActions.length > 10" style="margin-top: 12px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="actionsPage"
          :page-size="10"
          :total="recentActions.length"
          layout="total, prev, pager, next"
          size="small"
        />
      </div>
    </el-card>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card>
          <template #header><span>自动保护开关</span></template>
          <p style="color: #909399; font-size: 13px; margin-bottom: 15px">
            每种修复操作都有独立的保护开关。当连续失败时自动暂停该类操作，防止越修越坏。
          </p>
          <el-descriptions :column="1" border>
            <el-descriptions-item v-for="(state, name) in breakers" :key="name" :label="breakerLabel(String(name))">
              <el-tag :type="breakerType(state)" size="small">{{ breakerStateLabel(state) }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header><span>系统进程保护名单</span></template>
          <p style="color: #909399; font-size: 13px; margin-bottom: 15px">
            以下系统核心进程永远不会被 Agent 关闭，确保服务器基本运行不中断。
          </p>
          <el-table :data="pagedWhitelist" style="width: 100%" size="small">
            <el-table-column prop="name" label="进程名" />
          </el-table>
          <div v-if="whitelist.length > 10" style="margin-top: 12px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="wlPage"
              :page-size="wlPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="whitelist.length"
              layout="total, sizes, prev, pager, next"
              size="small"
              @update:page-size="wlPageSize = $event"
            />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 宝塔兼容设置已移至"宝塔面板"页面 -->
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { ElMessage, ElMessageBox } from 'element-plus'

const safety = ref<any>({})
const actionsPage = ref(1)
const wlPage = ref(1)
const wlPageSize = ref(10)

// ─── 维护窗口 ───
const maintenanceWindows = ref<any[]>([])
const maintenanceActive = ref(false)
const maintenanceDialogVisible = ref(false)
const maintenanceSaving = ref(false)
const maintenanceForm = ref({ name: '', reason: '', start: null as Date | null, end: null as Date | null })

async function fetchMaintenance() {
  try {
    const resp = await axios.get('/api/maintenance')
    maintenanceWindows.value = resp.data.windows || []
    maintenanceActive.value = resp.data.active || false
  } catch { /* 静默失败，不影响页面 */ }
}

function isWindowActive(w: any) {
  const now = Date.now()
  return new Date(w.start).getTime() <= now && now <= new Date(w.end).getTime()
}

function openMaintenanceDialog() {
  maintenanceForm.value = { name: '', reason: '', start: null, end: null }
  maintenanceDialogVisible.value = true
}

function quickWindow(hours: number) {
  const now = new Date()
  maintenanceForm.value.start = now
  maintenanceForm.value.end = new Date(now.getTime() + hours * 3600 * 1000)
}

async function createMaintenance() {
  const f = maintenanceForm.value
  if (!f.name.trim()) { ElMessage.warning('请填写窗口名称'); return }
  if (!f.start || !f.end) { ElMessage.warning('请选择起止时间'); return }
  maintenanceSaving.value = true
  try {
    await axios.post('/api/maintenance', {
      name: f.name.trim(),
      reason: f.reason.trim(),
      start: f.start.toISOString(),
      end: f.end.toISOString(),
    })
    ElMessage.success('维护窗口已创建，窗口期内自动修复将暂停')
    maintenanceDialogVisible.value = false
    fetchMaintenance()
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '创建失败')
  } finally {
    maintenanceSaving.value = false
  }
}

async function deleteMaintenance(row: any) {
  try {
    await ElMessageBox.confirm(`确认删除维护窗口「${row.name}」？删除后如窗口正在进行将立即恢复自动修复。`, '删除确认', {
      confirmButtonText: '确认删除', cancelButtonText: '取消', type: 'warning',
    })
  } catch { return }
  await axios.delete(`/api/maintenance/${row.id}`)
  ElMessage.success('已删除')
  fetchMaintenance()
}

const kb = computed(() => safety.value.kill_budget || {})
const breakers = computed(() => safety.value.circuit_breakers || {})
const recentActions = computed(() => safety.value.recent_actions || [])
const whitelist = computed(() => {
  const list = safety.value.whitelist || []
  return list.map((name: string) => ({ name: name.replace(' (hard)', '') }))
})

const pagedActions = computed(() => {
  const start = (actionsPage.value - 1) * 10
  return recentActions.value.slice(start, start + 10)
})

const pagedWhitelist = computed(() => {
  const start = (wlPage.value - 1) * wlPageSize.value
  return whitelist.value.slice(start, start + wlPageSize.value)
})

const modeLabel = computed(() => {
  const mode = safety.value.mode || 'normal'
  const labels: Record<string, string> = {
    normal: '正常运行',
    throttled: '降速运行（资源紧张）',
    minimal: '最小运行（仅核心功能）',
    survival: '存活模式（仅保命）',
    emergency: '紧急模式',
  }
  return labels[mode] || mode
})

const modeTagType = computed(() => {
  const mode = safety.value.mode || 'normal'
  return mode === 'normal' ? 'success' : 'warning'
})

function breakerLabel(name: string): string {
  const labels: Record<string, string> = {
    kill: '关闭进程',
    restart: '重启服务',
    ban_ip: '封禁 IP',
    clean_log: '清理日志',
    renew_cert: '续期证书',
  }
  return labels[name] || name
}

function breakerStateLabel(state: string): string {
  const labels: Record<string, string> = {
    closed: '正常（可以执行）',
    open: '已暂停（连续失败，暂停执行）',
    'half-open': '测试中（正在尝试恢复）',
  }
  return labels[state] || state
}

function breakerType(state: string) {
  if (state === 'open') return 'danger'
  if (state === 'half-open') return 'warning'
  return 'success'
}

function actionLabel(type: string): string {
  const labels: Record<string, string> = {
    kill: '关闭进程',
    sigterm: '关闭进程',
    sigkill: '强制关闭',
    nice: '调整优先级',
    restart: '重启服务',
    clean_log: '清理日志',
    rotate_log: '轮转日志',
    ban_ip: '封禁 IP',
    unban_ip: '解封 IP',
    renew_cert: '续期证书',
    reload_nginx: '重载 Nginx',
    clean_disk: '清理磁盘',
    run_script: '执行脚本',
    alert: '发送告警',
    snapshot: '创建快照',
  }
  return labels[type] || type || '-'
}

function formatTime(ts: string) {
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

async function fetchSafety() {
  const resp = await axios.get('/api/safety')
  safety.value = resp.data
}

async function emergencyStop() {
try {
  await ElMessageBox.confirm(
    '确认要紧急停止所有自动修复操作吗？停止后 Agent 将只监控和告警，不再执行任何修复操作。',
    '紧急停止确认',
    { confirmButtonText: '确认停止', cancelButtonText: '取消', type: 'warning' }
  )
} catch { return }
await axios.post('/api/emergency-stop')
fetchSafety()
}

async function emergencyResume() {
try {
  await ElMessageBox.confirm(
    '确认要恢复自动修复操作吗？Agent 将恢复执行自动修复规则。',
    '恢复确认',
    { confirmButtonText: '确认恢复', cancelButtonText: '取消', type: 'info' }
  )
} catch { return }
await axios.post('/api/emergency-resume')
fetchSafety()
}

onMounted(() => {
  fetchSafety()
  fetchMaintenance()
  setInterval(fetchSafety, 5000)
  setInterval(fetchMaintenance, 30000)
})
</script>
