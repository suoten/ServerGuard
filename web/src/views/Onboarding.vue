<template>
  <div class="onboarding-page">
    <div class="onboarding-container">
      <div class="onboarding-header">
        <h1>🚀 ServerGuard 初始化配置向导</h1>
        <p class="header-desc">几步完成初始化，立即开始保护你的服务器</p>
      </div>

      <el-steps :active="activeStep" align-center finish-status="success">
        <el-step title="基础信息" description="服务器名称、角色" />
        <el-step title="通知方式" description="告警通知渠道" />
        <el-step title="防护开关" description="选择要启用的守护" />
        <el-step title="安全策略" description="自动修复风险等级" />
        <el-step title="场景模板" description="快速应用推荐配置" />
        <el-step title="完成" description="开始使用" />
      </el-steps>

      <div class="step-content">
        <!-- Step 0: 基础信息 -->
        <div v-if="activeStep === 0" class="step-pane">
          <el-form label-width="120px" :model="formData.basic">
            <el-form-item label="服务器名称">
              <el-input v-model="formData.basic.serverName" placeholder="如：web-prod-01" />
            </el-form-item>
            <el-form-item label="服务器角色">
              <el-select v-model="formData.basic.role" placeholder="选择主要用途">
                <el-option label="Web 服务器" value="web" />
                <el-option label="数据库服务器" value="database" />
                <el-option label="API 服务器" value="api" />
                <el-option label="缓存服务器" value="cache" />
                <el-option label="文件服务器" value="file" />
                <el-option label="混合用途" value="mixed" />
              </el-select>
            </el-form-item>
            <el-form-item label="时区">
              <el-select v-model="formData.basic.timezone">
                <el-option label="Asia/Shanghai (UTC+8)" value="Asia/Shanghai" />
                <el-option label="UTC" value="UTC" />
                <el-option label="America/New_York" value="America/New_York" />
              </el-select>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 1: 通知方式 -->
        <div v-if="activeStep === 1" class="step-pane">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom: 20px">
            配置通知方式后，告警会自动推送到你的手机。支持双向交互：收到告警后直接回复指令即可远程控制。
          </el-alert>
          <el-form label-width="120px" :model="formData.notify">
            <el-form-item label="通知渠道">
              <el-checkbox-group v-model="formData.notify.channels">
                <el-checkbox label="wechat">企业微信</el-checkbox>
                <el-checkbox label="dingtalk">钉钉</el-checkbox>
                <el-checkbox label="telegram">Telegram</el-checkbox>
                <el-checkbox label="email">邮件</el-checkbox>
              </el-checkbox-group>
            </el-form-item>
            <el-form-item v-if="formData.notify.channels.includes('wechat')" label="企微 Webhook">
              <el-input v-model="formData.notify.wechatWebhook" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
            </el-form-item>
            <el-form-item v-if="formData.notify.channels.includes('dingtalk')" label="钉钉 Webhook">
              <el-input v-model="formData.notify.dingtalkWebhook" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." />
            </el-form-item>
            <el-form-item v-if="formData.notify.channels.includes('telegram')" label="TG Bot Token">
              <el-input v-model="formData.notify.telegramToken" placeholder="123456:ABC-DEF..." />
            </el-form-item>
            <el-form-item v-if="formData.notify.channels.includes('telegram')" label="TG Chat ID">
              <el-input v-model="formData.notify.telegramChatId" placeholder="如：123456789" />
            </el-form-item>
            <el-form-item v-if="formData.notify.channels.includes('email')" label="收件邮箱">
              <el-input v-model="formData.notify.emailTo" placeholder="admin@example.com" />
            </el-form-item>
            <el-form-item label="告警级别">
              <el-checkbox-group v-model="formData.notify.levels">
                <el-checkbox label="critical">严重</el-checkbox>
                <el-checkbox label="error">错误</el-checkbox>
                <el-checkbox label="warning">警告</el-checkbox>
                <el-checkbox label="info">提醒</el-checkbox>
              </el-checkbox-group>
            </el-form-item>
            <el-form-item label="双向交互">
              <el-switch v-model="formData.notify.bidirectional" />
              <span class="form-hint">开启后，告警附短编号，手机回复即可远程暂停/恢复自动修复</span>
            </el-form-item>
          </el-form>
          <el-button :loading="testing" @click="testNotify">发送测试通知</el-button>
          <el-tag v-if="testResult === 'ok'" type="success" style="margin-left: 12px">✅ 已发送</el-tag>
          <el-tag v-if="testResult === 'fail'" type="danger" style="margin-left: 12px">❌ 发送失败</el-tag>
        </div>

        <!-- Step 2: 防护开关 -->
        <div v-if="activeStep === 2" class="step-pane">
          <p class="step-desc">选择要启用的守护模块：</p>
          <div class="guard-grid">
            <div v-for="g in availableGuards" :key="g.id" class="guard-card" :class="{ active: formData.guards.includes(g.id) }" @click="toggleGuard(g.id)">
              <el-icon :size="24"><component :is="g.icon" /></el-icon>
              <span class="guard-name">{{ g.name }}</span>
              <span class="guard-desc">{{ g.desc }}</span>
            </div>
          </div>
        </div>

        <!-- Step 3: 安全策略 -->
        <div v-if="activeStep === 3" class="step-pane">
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 20px">
            ⚠️ 高风险操作（如重启服务、修改配置文件、封禁IP）默认仅提供建议，不会自动执行。
          </el-alert>
          <el-form label-width="180px" :model="formData.safety">
            <el-form-item label="自动修复风险等级">
              <el-radio-group v-model="formData.safety.autoFixLevel">
                <el-radio value="safe">仅安全操作（清理缓存、日志轮转等）</el-radio><br/>
                <el-radio value="medium">含中风险（重启非核心服务）</el-radio><br/>
                <el-radio value="manual">全部手动确认（最安全）</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="自动封禁攻击 IP">
              <el-switch v-model="formData.safety.autoBanIP" />
              <span class="form-hint">检测到暴力破解/扫描时自动封禁</span>
            </el-form-item>
            <el-form-item label="操作前自动备份配置">
              <el-switch v-model="formData.safety.autoBackup" />
              <span class="form-hint">修改任何配置文件前自动备份</span>
            </el-form-item>
            <el-form-item label="远程暂停开关">
              <el-switch v-model="formData.safety.remotePause" />
              <span class="form-hint">手机回复指令可一键暂停所有自动修复</span>
            </el-form-item>
          </el-form>
        </div>

        <!-- Step 4: 场景模板 -->
        <div v-if="activeStep === 4" class="step-pane">
          <p class="step-desc">选择一个场景模板快速应用推荐配置（可跳过）：</p>
          <div class="template-grid">
            <div
              v-for="t in templates" :key="t.id"
              class="template-card"
              :class="{ selected: formData.template === t.id }"
              @click="formData.template = formData.template === t.id ? '' : t.id"
            >
              <div class="template-icon">{{ t.icon }}</div>
              <div class="template-name">{{ t.name }}</div>
              <div class="template-desc">{{ t.desc }}</div>
              <div class="template-tags">
                <el-tag v-for="tag in t.tags" :key="tag" size="small" effect="plain">{{ tag }}</el-tag>
              </div>
            </div>
          </div>
          <el-button text @click="formData.template = ''">跳过，不使用模板</el-button>
        </div>

        <!-- Step 5: 完成 -->
        <div v-if="activeStep === 5" class="step-pane">
          <el-result icon="success" title="配置完成" sub-title="ServerGuard 已就绪，即将开始保护你的服务器">
            <template #extra>
              <el-button type="primary" size="large" :loading="saving" @click="saveConfig">完成并开始</el-button>
              <el-button @click="activeStep = 0">重新配置</el-button>
            </template>
          </el-result>
          <div class="config-preview">
            <h4>📋 配置预览</h4>
            <pre>{{ configPreview }}</pre>
          </div>
        </div>
      </div>

      <!-- 底部导航 -->
      <div class="step-footer" v-if="activeStep < 5">
        <el-button @click="activeStep = Math.max(0, activeStep - 1)" :disabled="activeStep === 0">上一步</el-button>
        <el-button type="primary" @click="activeStep++">下一步</el-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, markRaw } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { Cpu, Key, Connection, Document, Lock, Bell, Tools, DataLine } from '@element-plus/icons-vue'

const router = useRouter()
const activeStep = ref(0)
const saving = ref(false)
const testing = ref(false)
const testResult = ref('')

const formData = ref({
  basic: { serverName: '', role: '', timezone: 'Asia/Shanghai' },
  notify: {
    channels: ['wechat'],
    wechatWebhook: '',
    dingtalkWebhook: '',
    telegramToken: '',
    telegramChatId: '',
    emailTo: '',
    levels: ['critical', 'error', 'warning'],
    bidirectional: true,
  },
  guards: ['resource', 'disk', 'cert', 'security', 'log'] as string[],
  safety: {
    autoFixLevel: 'safe',
    autoBanIP: true,
    autoBackup: true,
    remotePause: true,
  },
  template: '',
})

const availableGuards = [
  { id: 'resource', name: '资源监控', desc: 'CPU/内存/磁盘', icon: markRaw(Cpu) },
  { id: 'disk', name: '磁盘守护', desc: '空间不足自动清理', icon: markRaw(Tools) },
  { id: 'cert', name: '证书守护', desc: 'SSL过期预警', icon: markRaw(Key) },
  { id: 'security', name: '安全防护', desc: '入侵检测+封禁', icon: markRaw(Lock) },
  { id: 'log', name: '日志守护', desc: '日志轮转+分析', icon: markRaw(Document) },
  { id: 'network', name: '网络守护', desc: '连接数+流量', icon: markRaw(Connection) },
  { id: 'service', name: '服务守护', desc: '进程存活检查', icon: markRaw(DataLine) },
  { id: 'attack', name: '攻击预警', desc: 'CC/注入检测', icon: markRaw(Bell) },
]

const templates = ref<any[]>([])

function toggleGuard(id: string) {
  const idx = formData.value.guards.indexOf(id)
  if (idx >= 0) formData.value.guards.splice(idx, 1)
  else formData.value.guards.push(id)
}

const configPreview = computed(() => {
  return JSON.stringify(formData.value, null, 2)
})

async function fetchTemplates() {
  try {
    const resp = await axios.get('/api/scene-templates')
    templates.value = (resp.data.templates || []).map((t: any) => ({
      id: t.id,
      name: t.name,
      desc: t.description,
      icon: t.icon || '📦',
      tags: t.tags || [],
    }))
  } catch {
    templates.value = [
      { id: 'web-server', name: 'Web 服务器', desc: 'Nginx + PHP + MySQL', icon: '🌐', tags: ['Nginx', 'PHP', 'MySQL'] },
      { id: 'database', name: '数据库服务器', desc: 'MySQL/PostgreSQL 专用', icon: '🗄️', tags: ['MySQL', '慢查询'] },
      { id: 'docker', name: 'Docker 宿主', desc: '容器化环境', icon: '🐳', tags: ['Docker', '容器'] },
    ]
  }
}

async function testNotify() {
  testing.value = true
  testResult.value = ''
  try {
    await axios.post('/api/onboarding/test-notify', formData.value.notify)
    testResult.value = 'ok'
  } catch {
    testResult.value = 'fail'
  } finally {
    testing.value = false
  }
}

async function saveConfig() {
  saving.value = true
  try {
    await axios.post('/api/onboarding/complete', formData.value)
    router.push('/dashboard')
  } catch {
    // 即使失败也跳转
    router.push('/dashboard')
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchTemplates()
})
</script>

<style scoped>
.onboarding-page {
  min-height: 100vh; background: #f0f2f5;
  display: flex; justify-content: center; padding: 40px 20px;
}
.onboarding-container {
  max-width: 800px; width: 100%; background: #fff;
  border-radius: 12px; padding: 32px; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
}
.onboarding-header { text-align: center; margin-bottom: 32px; }
.onboarding-header h1 { font-size: 24px; margin: 0 0 8px; }
.header-desc { color: #909399; font-size: 14px; }

.step-content { margin: 32px 0; min-height: 300px; }
.step-pane { animation: fadeIn 0.3s; }
.step-desc { color: #606266; margin-bottom: 16px; }
.form-hint { margin-left: 8px; font-size: 12px; color: #909399; }

.guard-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.guard-card {
  border: 2px solid #e4e7ed; border-radius: 8px; padding: 16px;
  text-align: center; cursor: pointer; transition: all 0.2s;
  display: flex; flex-direction: column; align-items: center; gap: 4px;
}
.guard-card:hover { border-color: #409eff; }
.guard-card.active { border-color: #409eff; background: #ecf5ff; }
.guard-name { font-size: 14px; font-weight: 600; }
.guard-desc { font-size: 12px; color: #909399; }

.template-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.template-card {
  border: 2px solid #e4e7ed; border-radius: 8px; padding: 16px;
  cursor: pointer; transition: all 0.2s; text-align: center;
}
.template-card:hover { border-color: #409eff; }
.template-card.selected { border-color: #409eff; background: #ecf5ff; }
.template-icon { font-size: 32px; margin-bottom: 8px; }
.template-name { font-weight: 600; margin-bottom: 4px; }
.template-desc { font-size: 12px; color: #909399; margin-bottom: 8px; }
.template-tags { display: flex; flex-wrap: wrap; gap: 4px; justify-content: center; }

.config-preview {
  margin-top: 20px; background: #f5f7fa; border-radius: 8px; padding: 16px;
  text-align: left; max-height: 300px; overflow: auto;
}
.config-preview h4 { margin: 0 0 8px; }
.config-preview pre { font-size: 12px; color: #606266; margin: 0; }

.step-footer { display: flex; justify-content: space-between; padding-top: 16px; border-top: 1px solid #f0f0f0; }

@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
</style>
