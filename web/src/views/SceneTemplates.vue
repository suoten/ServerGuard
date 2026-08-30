<template>
  <div class="scene-templates-page">
    <div class="page-header">
      <div class="header-left">
        <h2>场景模板</h2>
        <span class="header-sub">一键应用推荐配置 · 按场景预设守护策略</span>
      </div>
      <el-button :icon="Refresh" @click="fetchTemplates" :loading="loading">刷新</el-button>
    </div>

    <!-- 模板列表 -->
    <el-row :gutter="16">
      <el-col v-for="t in templates" :key="t.id" :xs="24" :sm="12" :md="8" style="margin-bottom: 16px">
        <el-card shadow="hover" class="template-card" @click="showDetail(t)">
          <div class="card-header">
            <span class="template-icon">{{ t.icon || '📦' }}</span>
            <div>
              <h3 class="template-title">{{ t.name }}</h3>
              <span class="template-id">{{ t.id }}</span>
            </div>
          </div>
          <p class="template-desc">{{ t.description }}</p>
          <div class="template-tags">
            <el-tag v-for="tag in (t.tags || [])" :key="tag" size="small" effect="plain" type="info">{{ tag }}</el-tag>
          </div>
          <div class="card-footer">
            <span class="meta-item">守护: {{ (t.guards || []).length }} 项</span>
            <span class="meta-item">规则: {{ (t.rules || []).length }} 条</span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 详情/应用抽屉 -->
    <el-drawer v-model="detailVisible" size="600px" :title="currentTemplate?.name || '模板详情'">
      <template v-if="currentTemplate">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="模板 ID">{{ currentTemplate.id }}</el-descriptions-item>
          <el-descriptions-item label="描述">{{ currentTemplate.description }}</el-descriptions-item>
          <el-descriptions-item label="适用场景">{{ currentTemplate.scenario || '通用' }}</el-descriptions-item>
        </el-descriptions>

        <!-- 包含的守护 -->
        <div class="detail-section">
          <h4>🛡️ 启用守护（{{ (currentTemplate.guards || []).length }} 项）</h4>
          <div class="guard-list">
            <el-tag v-for="g in (currentTemplate.guards || [])" :key="g" type="success" effect="plain" style="margin: 4px">
              {{ guardNameMap[g] || g }}
            </el-tag>
          </div>
        </div>

        <!-- 包含的规则 -->
        <div v-if="(currentTemplate.rules || []).length > 0" class="detail-section">
          <h4>📋 预设规则（{{ currentTemplate.rules.length }} 条）</h4>
          <el-table :data="(currentTemplate.rules || []).slice((rulePage-1)*ruleSize, rulePage*ruleSize)" stripe size="small">
            <el-table-column label="规则名" prop="name" min-width="150" />
            <el-table-column label="类型" prop="type" width="100" />
            <el-table-column label="阈值" prop="threshold" width="80" />
            <el-table-column label="动作" prop="action" width="100" />
          </el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="rulePage" v-model:page-size="ruleSize" :page-sizes="[10, 20, 50, 100]" :total="(currentTemplate.rules || []).length" layout="total, sizes, prev, pager, next" />
</div>
        </div>

        <!-- 通知配置 -->
        <div v-if="currentTemplate.notify" class="detail-section">
          <h4>🔔 通知配置</h4>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="通知渠道">{{ (currentTemplate.notify.channels || []).join(', ') }}</el-descriptions-item>
            <el-descriptions-item label="告警级别">{{ (currentTemplate.notify.levels || []).map(levelText).join(', ') }}</el-descriptions-item>
            <el-descriptions-item label="双向交互">{{ currentTemplate.notify.bidirectional ? '✅ 开启' : '❌ 关闭' }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- 安全策略 -->
        <div v-if="currentTemplate.safety" class="detail-section">
          <h4>🔒 安全策略</h4>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="自动修复等级">{{ safetyLevelLabel(currentTemplate.safety.autoFixLevel) }}</el-descriptions-item>
            <el-descriptions-item label="自动封禁IP">{{ currentTemplate.safety.autoBanIP ? '✅' : '❌' }}</el-descriptions-item>
            <el-descriptions-item label="远程暂停">{{ currentTemplate.safety.remotePause ? '✅' : '❌' }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <!-- 应用按钮 -->
        <div class="apply-section">
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 16px">
            应用模板将覆盖当前配置，请确认后操作。原配置可通过"重置"恢复。
          </el-alert>
          <el-button type="primary" size="large" :loading="applying" @click="applyTemplate" style="width: 100%">
            🚀 应用此模板
          </el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 应用结果 -->
    <el-dialog v-model="resultVisible" title="模板应用结果" width="500px">
      <el-result v-if="applyResult === 'success'" icon="success" title="应用成功" sub-title="配置已生效" />
      <el-result v-else icon="error" :title="applyError || '应用失败'" />
      <template #footer>
        <el-button @click="resultVisible = false">关闭</el-button>
        <el-button v-if="applyResult === 'success'" type="primary" @click="resultVisible = false">查看配置</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import axios from 'axios'

const loading = ref(false)
const templates = ref<any[]>([])
const detailVisible = ref(false)
const currentTemplate = ref<any>(null)
const applying = ref(false)
const resultVisible = ref(false)
const applyResult = ref('')
const rulePage = ref(1)
const ruleSize = ref(10)
const applyError = ref('')

const guardNameMap: Record<string, string> = {
  resource: '资源监控', disk: '磁盘守护', cert: '证书守护', security: '安全防护',
  log: '日志守护', network: '网络守护', service: '服务守护', attack: '攻击预警',
  database: '数据库守护', docker: 'Docker守护', config: '配置守护', traffic: '流量守护',
}

function safetyLevelLabel(level: string): string {
  const labels: Record<string, string> = {
    safe: '仅安全操作', medium: '含中风险', manual: '全部手动',
  }
  return labels[level] || level || '—'
}

function levelText(level: string): string {
  const labels: Record<string, string> = {
    critical: '严重', fatal: '致命', error: '错误', warning: '警告', info: '提醒',
  }
  return labels[level] || level || '—'
}

async function fetchTemplates() {
  loading.value = true
  try {
    const resp = await axios.get('/api/scene-templates')
    templates.value = resp.data.templates || []
  } catch {
    templates.value = [
      {
        id: 'web-server', name: 'Web 服务器', icon: '🌐',
        description: 'Nginx + PHP + MySQL 典型 Web 环境',
        tags: ['Nginx', 'PHP', 'MySQL'],
        guards: ['resource', 'disk', 'cert', 'security', 'log', 'service', 'attack'],
        rules: [{ name: '磁盘空间', type: 'disk', threshold: '85%', action: '清理缓存' }],
        notify: { channels: ['wechat'], levels: ['critical', 'error', 'warning'], bidirectional: true },
        safety: { autoFixLevel: 'safe', autoBanIP: true, remotePause: true },
      },
      {
        id: 'database', name: '数据库服务器', icon: '🗄️',
        description: 'MySQL/PostgreSQL 专用优化配置',
        tags: ['MySQL', '慢查询', '连接数'],
        guards: ['resource', 'disk', 'log', 'service', 'database'],
        rules: [{ name: '慢查询', type: 'db', threshold: '5s', action: '记录' }],
        notify: { channels: ['wechat'], levels: ['critical', 'error'], bidirectional: true },
        safety: { autoFixLevel: 'manual', autoBanIP: false, remotePause: true },
      },
      {
        id: 'docker', name: 'Docker 宿主', icon: '🐳',
        description: '容器化环境，自动清理无用镜像',
        tags: ['Docker', '容器', '镜像'],
        guards: ['resource', 'disk', 'docker', 'service', 'network'],
        rules: [{ name: '容器异常退出', type: 'docker', threshold: '3次', action: '重启容器' }],
        notify: { channels: ['dingtalk'], levels: ['critical', 'error', 'warning'], bidirectional: true },
        safety: { autoFixLevel: 'medium', autoBanIP: true, remotePause: true },
      },
    ]
  } finally {
    loading.value = false
  }
}

function showDetail(t: any) {
  currentTemplate.value = t
  detailVisible.value = true
}

async function applyTemplate() {
  if (!currentTemplate.value) return
  applying.value = true
  applyResult.value = ''
  applyError.value = ''
  try {
    await axios.post(`/api/scene-templates/${currentTemplate.value.id}/apply`)
    applyResult.value = 'success'
    resultVisible.value = true
    detailVisible.value = false
  } catch (err: any) {
    applyResult.value = 'fail'
    applyError.value = err?.response?.data?.error || '应用失败，请检查后端连接'
    resultVisible.value = true
  } finally {
    applying.value = false
  }
}

onMounted(() => {
  fetchTemplates()
})
</script>

<style scoped>
.scene-templates-page { padding: 20px; }
.page-header {
  display: flex; justify-content: space-between; align-items: flex-start;
  margin-bottom: 20px;
}
.header-left h2 { margin: 0; font-size: 20px; }
.header-sub { font-size: 13px; color: #909399; }

.template-card { cursor: pointer; transition: all 0.2s; }
.template-card:hover { transform: translateY(-2px); }
.card-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.template-icon { font-size: 32px; }
.template-title { margin: 0; font-size: 16px; }
.template-id { font-size: 12px; color: #c0c4cc; }
.template-desc { color: #606266; font-size: 13px; margin: 0 0 12px; line-height: 1.6; }
.template-tags { margin-bottom: 12px; }
.card-footer { display: flex; gap: 16px; font-size: 12px; color: #909399; border-top: 1px solid #f0f0f0; padding-top: 12px; }

.detail-section { margin-top: 24px; }
.detail-section h4 { margin-bottom: 12px; }
.apply-section { margin-top: 32px; padding-top: 16px; border-top: 1px solid #f0f0f0; }
</style>
