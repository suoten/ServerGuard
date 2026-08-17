<template>
  <div>
    <el-card>
      <template #header><span>系统设置</span></template>
      <el-tabs>
        <el-tab-pane label="基本配置">
          <el-form label-width="140px" v-loading="loading">
            <el-form-item label="采集间隔">
              <el-input-number v-model="settings.collect_interval" :min="1" :max="60" /> 秒
            </el-form-item>
            <el-form-item label="运行模式">
              <el-switch v-model="settings.learn_mode" active-text="只告警不修复" inactive-text="自动修复" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">学习模式下只观察告警，不执行修复操作</span>
            </el-form-item>
            <el-form-item label="最大内存">
              <el-input-number v-model="settings.max_memory_mb" :min="32" :max="512" /> MB
              <span style="margin-left: 10px; color: #909399; font-size: 12px">Agent 自身内存上限</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="通知设置">
          <el-form label-width="140px" v-loading="notifyLoading">
            <el-divider content-position="left">WxPusher 推送（免费多平台）</el-divider>
            <el-form-item label="AppToken">
              <el-input v-model="notify.wxpusher_app_token" placeholder="APP_xxx，从 WxPusher 后台获取" show-password />
            </el-form-item>
            <el-form-item label="UID">
              <el-input v-model="notify.wxpusher_uid" placeholder="UID_xxx，扫码关注应用后获取" show-password />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">
                <a href="https://wxpusher.zjiecode.com/admin/" target="_blank" style="color: #409eff">点击前往 WxPusher 后台</a>，创建应用获取 AppToken，扫码关注后获取 UID
              </span>
            </el-form-item>

            <el-divider content-position="left">邮件推送</el-divider>
            <el-form-item label="SMTP 服务器">
              <el-input v-model="notify.smtp_host" placeholder="smtp.gmail.com" />
            </el-form-item>
            <el-form-item label="SMTP 端口">
              <el-input v-model="notify.smtp_port" placeholder="587" style="width: 120px" />
            </el-form-item>
            <el-form-item label="发件邮箱">
              <el-input v-model="notify.smtp_user" placeholder="sender@gmail.com" />
            </el-form-item>
            <el-form-item label="邮箱密码">
              <el-input v-model="notify.smtp_password" type="password" placeholder="密码或应用专用密码" show-password />
            </el-form-item>
            <el-form-item label="收件邮箱">
              <el-input v-model="notify.email_to" placeholder="admin@example.com（多个用逗号分隔）" />
            </el-form-item>

            <el-divider content-position="left">每日巡检报告</el-divider>
            <el-form-item label="巡检报告推送">
              <el-switch v-model="notify.digest_enabled" active-text="开启" inactive-text="关闭" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每天定时推送巡检报告（健康评分/资源峰值/网站/证书/告警/自愈汇总）</span>
            </el-form-item>
            <el-form-item label="报告推送时间">
              <el-input-number v-model="notify.digest_hour" :min="0" :max="23" /> 点
            </el-form-item>
            <el-form-item label="报告预览">
              <el-button @click="previewReport" :loading="reportLoading">在线预览</el-button>
              <el-button type="primary" plain @click="sendReportNow" :loading="reportSending">立即发送到所有渠道</el-button>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveNotify" :loading="notifySaving">保存通知设置</el-button>
              <el-button @click="testNotify" :loading="testing">发送测试通知</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="面板密码">
          <el-form label-width="140px">
            <el-form-item label="登录用户名">
              <el-input v-model="settings.username" placeholder="admin" />
            </el-form-item>
            <el-form-item label="新密码">
              <el-input v-model="newPassword" type="password" placeholder="留空则不修改" show-password />
            </el-form-item>
            <el-form-item label="确认密码">
              <el-input v-model="confirmPassword" type="password" placeholder="再次输入新密码" show-password />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="savePassword" :loading="saving">保存密码</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="证书配置">
          <el-form label-width="140px">
            <el-form-item label="自动续期天数">
              <el-input-number v-model="settings.auto_renew_days" :min="1" :max="30" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">证书剩余天数低于此值时自动续期</span>
            </el-form-item>
            <el-form-item label="证书扫描端口">
              <el-input v-model="certPortsStr" placeholder="443, 8443" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">扫描这些端口上的 HTTPS 证书</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="安全设置">
          <el-form label-width="140px">
            <el-form-item label="进程关闭上限（每小时）">
              <el-input-number v-model="settings.kill_budget_hourly" :min="0" :max="50" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每小时最多关闭进程次数</span>
            </el-form-item>
            <el-form-item label="进程关闭上限（每天）">
              <el-input-number v-model="settings.kill_budget_daily" :min="0" :max="100" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每天最多关闭进程次数</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 巡检报告预览对话框 -->
    <el-dialog v-model="reportDialogVisible" title="每日巡检报告预览" width="560px">
      <pre class="report-preview">{{ reportContent }}</pre>
      <template #footer>
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="sendReportNow" :loading="reportSending">发送到所有渠道</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'

const loading = ref(false)
const saving = ref(false)
const newPassword = ref('')
const confirmPassword = ref('')
const certPortsStr = ref('443, 8443')

const notifyLoading = ref(false)
const notifySaving = ref(false)
const testing = ref(false)

// ─── 每日巡检报告 ───
const reportLoading = ref(false)
const reportSending = ref(false)
const reportDialogVisible = ref(false)
const reportContent = ref('')

async function previewReport() {
  reportLoading.value = true
  try {
    const resp = await axios.get('/api/report/daily')
    reportContent.value = resp.data.report
    reportDialogVisible.value = true
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '获取报告失败')
  } finally {
    reportLoading.value = false
  }
}

async function sendReportNow() {
  reportSending.value = true
  try {
    await axios.post('/api/report/daily/send')
    ElMessage.success('巡检报告已推送到所有已启用渠道')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '发送失败')
  } finally {
    reportSending.value = false
  }
}

const settings = reactive({
  collect_interval: 5,
  learn_mode: true,
  max_memory_mb: 80,
  auto_renew_days: 14,
  kill_budget_hourly: 5,
  kill_budget_daily: 20,
  username: 'admin',
})

const notify = reactive({
wxpusher_app_token: '',
wxpusher_uid: '',
smtp_host: '',
smtp_port: '587',
smtp_user: '',
smtp_password: '',
email_to: '',
digest_enabled: false,
digest_hour: 8,
silence_enabled: false,
})

async function fetchSettings() {
  loading.value = true
  try {
    const resp = await axios.get('/api/settings')
    const data = resp.data
    Object.assign(settings, data)
    if (data.cert_ports) {
      certPortsStr.value = data.cert_ports.join(', ')
    }
  } catch (err) {
    ElMessage.error('加载设置失败')
  } finally {
    loading.value = false
  }
}

async function fetchNotifySettings() {
  notifyLoading.value = true
  try {
    const resp = await axios.get('/api/notify/settings')
    Object.assign(notify, resp.data)
  } catch (err) {
    ElMessage.error('加载通知设置失败')
  } finally {
    notifyLoading.value = false
  }
}

async function saveSettings() {
  saving.value = true
  try {
    await axios.post('/api/settings', settings)
    ElMessage.success('设置已保存')
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}

async function saveNotify() {
  notifySaving.value = true
  try {
    await axios.post('/api/notify/settings', notify)
    ElMessage.success('通知设置已保存并生效')
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    notifySaving.value = false
  }
}

async function testNotify() {
  testing.value = true
  try {
    const resp = await axios.post('/api/notify/test')
    ElMessage.success(resp.data.message || '测试通知已发送')
  } catch (err: any) {
    const msg = err?.response?.data?.error || '发送失败'
    ElMessage.error(msg)
  } finally {
    testing.value = false
  }
}

async function savePassword() {
  if (newPassword.value !== confirmPassword.value) {
    ElMessage.error('两次输入的密码不一致')
    return
  }
  if (newPassword.value && newPassword.value.length < 6) {
    ElMessage.warning('密码至少 6 位')
    return
  }
  saving.value = true
  try {
    await axios.post('/api/settings', {
      ...settings,
      new_password: newPassword.value,
    })
    ElMessage.success('密码已保存，下次登录生效')
    newPassword.value = ''
    confirmPassword.value = ''
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchSettings()
  fetchNotifySettings()
})
</script>

<style scoped>
.report-preview {
  margin: 0;
  padding: 16px;
  background: #f8fafd;
  border: 1px solid #e6eaf2;
  border-radius: 10px;
  font-size: 13px;
  line-height: 1.8;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 60vh;
  overflow-y: auto;
  font-family: inherit;
  color: #1e293b;
}
html.dark .report-preview {
  background: #1d2433;
  border-color: #33415584;
  color: #e2e8f0;
}
</style>
