<template>
  <div class="rules-page">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>规则管理 <el-tag size="small" type="info">共 {{ filteredRules.length }} 条</el-tag></span>
          <div class="header-actions">
            <el-input v-model="searchQuery" placeholder="搜索ID/名称/模块..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
            <el-button type="success" @click="loadDefaultRules" :loading="loadingDefaults">加载常用预设规则</el-button>
            <el-button type="primary" @click="showAddRule = true">添加规则</el-button>
          </div>
        </div>
      </template>

      <el-table :data="pagedRules" stripe v-loading="loading">
        <el-table-column prop="id" label="规则ID" width="150" />
        <el-table-column prop="name" label="名称" width="200" />
        <el-table-column prop="module" label="模块" width="120">
          <template #default="{ row }">
            <el-tag :type="moduleTagType(row.module)" size="small">{{ moduleLabel(row.module) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="priority" label="优先级" width="80" />
        <el-table-column prop="alert_level" label="告警级别" width="100">
          <template #default="{ row }">
            <el-tag :type="levelTagType(row.alert_level)">{{ levelLabel(row.alert_level) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="启用" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" @change="toggleRule(row)" />
          </template>
        </el-table-column>
<el-table-column prop="needs_confirmation" label="需确认" width="80">
<template #default="{ row }">
<el-tag v-if="row.needs_confirmation" type="warning" size="small">是</el-tag>
<el-tag v-else type="info" size="small">否</el-tag>
</template>
</el-table-column>
        <el-table-column label="操作" width="200">
          <template #default="{ row }">
            <el-button size="small" @click="editRule(row)">编辑</el-button>
            <el-button size="small" @click="testRule(row)">测试</el-button>
            <el-button size="small" type="danger" @click="deleteRule(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 30px 0; text-align: center">
            <p style="color: #909399; margin-bottom: 10px">规则正在自动加载中...</p>
            <p style="color: #c0c4cc; font-size: 13px; margin-bottom: 15px">系统已内置常用安全规则，首次打开时自动加载</p>
          </div>
        </template>
      </el-table>

      <!-- 分页 -->
      <div style="margin-top: 16px; display: flex; justify-content: flex-end" v-if="filteredRules.length > 0">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredRules.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>

    <el-dialog v-model="showAddRule" title="添加规则" width="60%">
      <el-form :model="newRule" label-width="100px">
        <el-form-item label="名称"><el-input v-model="newRule.name" /></el-form-item>
        <el-form-item label="模块">
          <el-select v-model="newRule.module">
            <el-option label="资源守护" value="resource" />
            <el-option label="服务守护" value="service" />
            <el-option label="安全防护" value="security" />
            <el-option label="日志防护" value="log" />
            <el-option label="网络守护" value="network" />
            <el-option label="系统守护" value="system" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="newRule.priority" :min="1" :max="100" /></el-form-item>
        <el-form-item label="告警级别">
          <el-select v-model="newRule.alert_level">
            <el-option label="信息" value="info" />
            <el-option label="警告" value="warning" />
            <el-option label="错误" value="error" />
            <el-option label="严重" value="critical" />
            <el-option label="致命" value="fatal" />
          </el-select>
        </el-form-item>
        <el-form-item label="需确认">
          <el-switch v-model="newRule.needs_confirmation" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddRule = false">取消</el-button>
        <el-button type="primary" @click="addRule">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showEditRule" title="编辑规则" width="60%">
      <el-form :model="editRuleData" label-width="100px">
        <el-form-item label="名称"><el-input v-model="editRuleData.name" /></el-form-item>
        <el-form-item label="模块">
          <el-select v-model="editRuleData.module">
            <el-option label="资源守护" value="resource" />
            <el-option label="服务守护" value="service" />
            <el-option label="安全防护" value="security" />
            <el-option label="日志防护" value="log" />
            <el-option label="网络守护" value="network" />
            <el-option label="系统守护" value="system" />
          </el-select>
        </el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="editRuleData.priority" :min="1" :max="100" /></el-form-item>
        <el-form-item label="告警级别">
          <el-select v-model="editRuleData.alert_level">
            <el-option label="信息" value="info" />
            <el-option label="警告" value="warning" />
            <el-option label="错误" value="error" />
            <el-option label="严重" value="critical" />
            <el-option label="致命" value="fatal" />
          </el-select>
        </el-form-item>
        <el-form-item label="需确认">
          <el-switch v-model="editRuleData.needs_confirmation" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showEditRule = false">取消</el-button>
        <el-button type="primary" @click="saveEditRule">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showTestResult" title="规则测试结果" width="600px">
      <div class="test-result-card" v-if="testResult">
        <!-- 摘要 -->
        <el-alert
          :title="testResult.summary"
          :type="testResult.would_execute ? 'warning' : 'info'"
          :description="testResult.execution_mode"
          show-icon
          :closable="false"
          style="margin-bottom: 16px"
        />

        <!-- 基本信息 -->
        <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
          <el-descriptions-item label="规则名称">{{ testResult.rule_name }}</el-descriptions-item>
          <el-descriptions-item label="规则ID">{{ testResult.rule_id }}</el-descriptions-item>
          <el-descriptions-item label="优先级">{{ testResult.priority }}</el-descriptions-item>
          <el-descriptions-item label="告警级别">
            <el-tag :type="alertLevelTagType(testResult.alert_level)" size="small">{{ levelLabel(testResult.alert_level) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="触发条件" :span="2">{{ testResult.trigger }}</el-descriptions-item>
          <el-descriptions-item label="冷却时间">{{ testResult.cooldown }}</el-descriptions-item>
          <el-descriptions-item label="触发限制">{{ testResult.max_triggers }}</el-descriptions-item>
        </el-descriptions>

        <!-- 执行步骤 -->
        <div class="actions-section">
          <div class="section-title">将要执行的操作</div>
          <el-steps direction="vertical" :active="-1">
            <el-step
              v-for="action in testResult.actions"
              :key="action.step"
              :title="`${action.step}. ${action.action}`"
              :description="`${action.detail}${action.on_fail !== '—' ? '  ·  ' + action.on_fail : ''}`"
            />
          </el-steps>
        </div>

        <!-- 提示 -->
        <el-text type="info" size="small" style="display: block; margin-top: 16px">
          以上为模拟结果，实际触发时会经过安全检查（冷却期、白名单、Kill预算等）后才会执行。
        </el-text>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'
import { Search } from '@element-plus/icons-vue'

const rules = ref([])
const loading = ref(false)
const loadingDefaults = ref(false)
const showAddRule = ref(false)
const showTestResult = ref(false)
const testResult = ref(null)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)
const newRule = reactive({
  name: '', module: 'resource', priority: 50, alert_level: 'warning', needs_confirmation: false
})

const showEditRule = ref(false)
const editRuleData = reactive({
  id: '', name: '', module: 'resource', priority: 50, alert_level: 'warning', needs_confirmation: false
})

const filteredRules = computed(() => {
  if (!searchQuery.value) return rules.value
  const q = searchQuery.value.toLowerCase()
  return rules.value.filter((r) =>
    r.id?.toLowerCase().includes(q) ||
    r.name?.toLowerCase().includes(q) ||
    r.module?.toLowerCase().includes(q)
  )
})
const pagedRules = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredRules.value.slice(start, start + pageSize.value)
})

// 预设规则模板
const defaultRules = [
  { name: 'CPU 使用率过高', module: 'resource', priority: 80, alert_level: 'warning', needs_confirmation: false },
  { name: '内存使用率过高', module: 'resource', priority: 80, alert_level: 'warning', needs_confirmation: false },
  { name: '磁盘空间不足', module: 'resource', priority: 90, alert_level: 'critical', needs_confirmation: false },
  { name: '进程异常退出', module: 'service', priority: 70, alert_level: 'error', needs_confirmation: false },
  { name: '服务端口不可达', module: 'service', priority: 85, alert_level: 'critical', needs_confirmation: true },
  { name: 'SSH 暴力破解检测', module: 'security', priority: 95, alert_level: 'critical', needs_confirmation: false },
  { name: '异常登录检测', module: 'security', priority: 90, alert_level: 'critical', needs_confirmation: true },
  { name: '可疑文件检测', module: 'security', priority: 75, alert_level: 'warning', needs_confirmation: true },
  { name: '日志文件增长异常', module: 'log', priority: 50, alert_level: 'warning', needs_confirmation: false },
  { name: '网络连接数过多', module: 'network', priority: 60, alert_level: 'warning', needs_confirmation: false },
  { name: '系统负载过高', module: 'system', priority: 75, alert_level: 'warning', needs_confirmation: false },
  { name: '僵尸进程过多', module: 'system', priority: 40, alert_level: 'info', needs_confirmation: false },
  { name: '证书即将过期', module: 'security', priority: 70, alert_level: 'warning', needs_confirmation: false },
  { name: '磁盘IO异常', module: 'system', priority: 65, alert_level: 'warning', needs_confirmation: false },
  { name: 'Docker 容器异常', module: 'service', priority: 80, alert_level: 'error', needs_confirmation: false },
]

function levelTagType(level) {
  const types = { info: 'info', warning: 'warning', error: '', critical: 'danger', fatal: 'danger' }
  return types[level] || 'info'
}
function levelLabel(level) {
  const labels = { info: '信息', warning: '警告', error: '错误', critical: '严重', fatal: '致命' }
  return labels[level] || level
}
function moduleLabel(m) {
  const labels = { resource: '资源守护', service: '服务守护', security: '安全防护', log: '日志防护', network: '网络守护', system: '系统守护' }
  return labels[m] || m
}
function moduleTagType(m) {
  const types = { resource: 'primary', service: 'success', security: 'danger', log: 'info', network: 'warning', system: '' }
  return types[m] || 'info'
}

async function loadRules() {
  loading.value = true
  try {
    const resp = await axios.get('/api/rules')
    rules.value = resp.data.rules || []
  } catch {
    ElMessage.error('加载规则失败')
  } finally {
    loading.value = false
  }
}

async function loadDefaultRules() {
  try {
    await ElMessageBox.confirm(
      `将添加 ${defaultRules.length} 条预设规则（CPU/内存/磁盘/SSH/证书等常用监控规则），已存在的同名规则会跳过。确认添加？`,
      '加载预设规则',
      { confirmButtonText: '确认添加', cancelButtonText: '取消', type: 'info' }
    )
  } catch { return }

  loadingDefaults.value = true
  let added = 0
  let skipped = 0
  for (const rule of defaultRules) {
    const exists = rules.value.some(r => r.name === rule.name)
    if (exists) {
      skipped++
      continue
    }
    try {
      const resp = await axios.post('/api/rules', rule)
      if (resp.status === 200 || resp.status === 201) added++
    } catch {
      // continue on error
    }
  }
  loadingDefaults.value = false
  if (added > 0) {
    ElMessage.success(`成功添加 ${added} 条预设规则${skipped > 0 ? `，跳过 ${skipped} 条已存在的` : ''}`)
    loadRules()
  } else if (skipped > 0) {
    ElMessage.info(`所有预设规则已存在，跳过 ${skipped} 条`)
  }
}

async function addRule() {
  try {
    const resp = await axios.post('/api/rules', newRule)
    if (resp.status === 200 || resp.status === 201) {
      ElMessage.success('规则添加成功')
      showAddRule.value = false
      loadRules()
    }
  } catch {
    ElMessage.error('添加规则失败')
  }
}

function editRule(row) {
  editRuleData.id = row.id
  editRuleData.name = row.name
  editRuleData.module = row.module
  editRuleData.priority = row.priority
  editRuleData.alert_level = row.alert_level
  editRuleData.needs_confirmation = row.needs_confirmation
  showEditRule.value = true
}

async function saveEditRule() {
  try {
    const resp = await axios.put(`/api/rules/${editRuleData.id}`, {
      name: editRuleData.name,
      module: editRuleData.module,
      priority: editRuleData.priority,
      alert_level: editRuleData.alert_level,
      needs_confirmation: editRuleData.needs_confirmation,
    })
    if (resp.status === 200) {
      ElMessage.success('规则更新成功')
      showEditRule.value = false
      loadRules()
    }
  } catch {
    ElMessage.error('更新规则失败')
  }
}

async function testRule(row) {
  try {
    const resp = await axios.post('/api/rules/test', { rule: row, sample: {} })
    testResult.value = resp.data
    showTestResult.value = true
  } catch {
    ElMessage.error('测试失败')
  }
}

function alertLevelTagType(level) {
  const types = { '信息': 'info', '警告': 'warning', '错误': '', '严重': 'danger', '致命': 'danger' }
  return types[level] || 'info'
}

async function deleteRule(row) {
  try {
    await ElMessageBox.confirm(`确认删除规则 ${row.name}?`, '删除规则', { type: 'warning' })
    const resp = await axios.delete(`/api/rules/${row.id}`)
    if (resp.status === 200) {
      ElMessage.success('规则删除成功')
      loadRules()
    }
  } catch {}
}

async function toggleRule(row) {
  try {
    await axios.put(`/api/rules/${row.id}/toggle`, { enabled: row.enabled })
    ElMessage.success(`规则 ${row.name} 已${row.enabled ? '启用' : '禁用'}`)
  } catch {
    ElMessage.error('操作失败')
    row.enabled = !row.enabled
  }
}

onMounted(() => {
  loadRules()
})
</script>

<style scoped>
.rules-page { padding: 20px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 10px; align-items: center; }
.test-result-card { padding: 0 8px; }
.section-title { font-weight: 600; margin-bottom: 12px; color: #303133; }
.actions-section { margin-top: 8px; }
</style>
