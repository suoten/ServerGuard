<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>面板环境检测</span>
          <el-button type="primary" @click="rescan" :loading="scanning">重新扫描</el-button>
        </div>
      </template>

      <div v-if="!baota.detected" class="empty-guide">
        <el-icon style="font-size: 48px; color: #c0c4cc; margin-bottom: 15px"><Setting /></el-icon>
        <p style="font-size: 16px; color: #606266; margin-bottom: 8px">未检测到管理面板</p>
        <p style="color: #909399; margin-bottom: 20px">Agent 会自动探测本机是否安装了宝塔等管理面板。</p>
        <el-alert type="info" :closable="false" style="max-width: 500px">
          <template #title>说明</template>
          <p style="font-size: 13px; line-height: 1.8">
            • Windows 服务器通常不安装宝塔面板<br>
            • 在 Linux 服务器上，Agent 会自动检测宝塔安装路径、版本和 API 能力<br>
            • 检测到宝塔后，证书续期会优先走宝塔 API（不消耗 ACME 配额）<br>
            • ServerGuard 始终以安全保护模式运行，不会误杀面板进程或服务
          </p>
        </el-alert>
      </div>

      <el-descriptions v-else :column="2" border v-loading="loading">
        <el-descriptions-item label="检测到宝塔">
          <el-tag type="success">是</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="版本">{{ baota.version || '-' }}</el-descriptions-item>
        <el-descriptions-item label="面板类型">{{ baota.panel_type || '-' }}</el-descriptions-item>
        <el-descriptions-item label="安装路径">{{ baota.install_path || '-' }}</el-descriptions-item>
        <el-descriptions-item label="API 状态">
          <el-tag :type="baota.detected ? 'success' : 'warning'">
            {{ baota.detected ? '已检测' : '未检测' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="面板路径">{{ baota.install_path || '-' }}</el-descriptions-item>

        <el-divider content-position="left">API 能力</el-divider>
        <el-row v-if="baota.capabilities">
          <el-col v-for="(enabled, name) in baota.capabilities" :key="name" :span="6">
            <el-tag :type="enabled ? 'success' : 'info'" style="margin: 5px">
              {{ capabilityLabel(String(name)) }}: {{ enabled ? '✓ 支持' : '✗ 不支持' }}
            </el-tag>
          </el-col>
        </el-row>
      </el-descriptions>
    </el-card>

    <!-- 安全保护设置 -->
    <el-card v-if="baota.detected" style="margin-top: 20px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>安全保护设置</span>
          <el-tag type="success" size="small">始终启用</el-tag>
        </div>
      </template>
      <el-alert type="success" :closable="false" style="margin-bottom: 20px">
        <template #title>安全保护说明</template>
        <p style="font-size: 13px; line-height: 1.8; margin: 0">
          ServerGuard 始终以安全保护模式运行，自动保护服务器关键进程和托管服务。
          所有可能影响业务运行的自动修复操作（如进程关闭、服务重启、磁盘清理）均经过安全校验，
          确保不会导致服务器或面板崩溃。
        </p>
      </el-alert>
      <el-form label-width="180px" v-loading="baotaSaving">
        <el-form-item label="服务守护方式">
          <el-switch
            v-model="baotaConfig.baotaAutoRestart"
            active-text="使用面板命令重启（/etc/init.d/xxx）"
            inactive-text="禁用自动重启"
          />
        </el-form-item>
        <el-form-item label="磁盘清理范围">
          <el-select v-model="baotaConfig.baotaCleanupScope" style="width: 100%">
            <el-option label="完全禁用（推荐）" value="disabled" />
            <el-option label="仅清理 /var/log（系统日志）" value="var_log_only" />
          </el-select>
        </el-form-item>
        <el-form-item label="日志轮转策略">
          <el-select v-model="baotaConfig.baotaLogRotation" style="width: 100%">
            <el-option label="完全禁用（推荐）" value="disabled" />
            <el-option label="仅告警通知" value="notify_only" />
          </el-select>
        </el-form-item>
        <el-form-item label="面板自动守护">
          <el-switch
            v-model="baotaConfig.baotaPanelAutoRestart"
            active-text="面板异常自动恢复（推荐）"
            inactive-text="不自动恢复"
          />
          <p style="color: #909399; font-size: 12px; margin: 4px 0 0">
            ServerGuard 会定期检查面板进程，如果进程异常会自动执行 /etc/init.d/bt restart 恢复
          </p>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveBaotaConfig">保存设置</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { Setting } from '@element-plus/icons-vue'

const baota = ref<any>({})
const loading = ref(false)
const scanning = ref(false)
const baotaSaving = ref(false)
const baotaConfig = ref({
  baotaAutoRestart: true,
  baotaCleanupScope: 'disabled',
  baotaLogRotation: 'disabled',
  baotaPanelAutoRestart: true,
})

async function fetchBaoTa() {
  loading.value = true
  try {
    const resp = await axios.get('/api/baota/status')
    baota.value = resp.data
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

async function rescan() {
  scanning.value = true
  try {
    await axios.post('/api/baota/rescan')
    await fetchBaoTa()
    if (baota.value.detected) {
      ElMessage.success('检测到宝塔面板')
    } else {
      ElMessage.info('未检测到宝塔面板')
    }
  } catch (err) {
    ElMessage.error('扫描失败')
  } finally {
    scanning.value = false
  }
}

async function fetchSettings() {
  try {
    const resp = await axios.get('/api/settings')
    const data = resp.data
    baotaConfig.value.baotaAutoRestart = data.baota_service_mgr ?? true
    baotaConfig.value.baotaCleanupScope = data.baota_cleanup_scope || 'disabled'
    baotaConfig.value.baotaLogRotation = data.baota_log_rotation || 'disabled'
  } catch (err) {
    console.error('Failed to fetch settings:', err)
  }
}

async function saveBaotaConfig() {
  baotaSaving.value = true
  try {
    await axios.post('/api/settings', {
      baota_safe_mode: 'true',
      baota_service_mgr: baotaConfig.value.baotaAutoRestart,
      baota_cleanup_scope: baotaConfig.value.baotaCleanupScope,
      baota_log_rotation: baotaConfig.value.baotaLogRotation,
    })
    ElMessage.success('安全保护设置已保存并生效')
  } catch (err: any) {
    ElMessage.error('保存失败: ' + (err?.response?.data?.error || err.message))
  } finally {
    baotaSaving.value = false
  }
}

function capabilityLabel(name: string): string {
  const labels: Record<string, string> = {
    ssl_renew: 'SSL 续期',
    site_list: '站点列表',
    config_get: '配置读取',
    config_set: '配置修改',
    service_restart: '服务重启',
  }
  return labels[name] || name
}

onMounted(() => {
  fetchBaoTa()
  fetchSettings()
})
</script>

<style scoped>
.empty-guide {
  text-align: center;
  padding: 40px 20px;
}
</style>
