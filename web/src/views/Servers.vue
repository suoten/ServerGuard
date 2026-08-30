<template>
  <div>
    <!-- Hub 模式状态条 -->
    <el-alert
      v-if="!loading && servers.length <= 1"
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    >
      当前为单机模式，仅显示本机。如需管理多台服务器，请在
      <router-link to="/settings" style="color: #409eff; font-weight: 600">系统设置 → 多服务器管理</router-link>
      中部署 Hub 并连接各服务器 Agent。
    </el-alert>

    <el-alert
      v-if="hubMode"
      type="success"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    >
      已启用多机集中管控，当前管理 {{ servers.length }} 台服务器。
    </el-alert>

    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>服务器列表</span>
          <div style="display: flex; gap: 8px">
            <el-button text @click="fetchServers">刷新</el-button>
          </div>
        </div>
      </template>
      <el-table :data="pagedServers" v-loading="loading">
        <el-table-column prop="hostname" label="主机名" min-width="120" />
        <el-table-column prop="ip" label="IP 地址" width="140" />
        <el-table-column prop="id" label="Agent ID" width="170" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.id">{{ row.id }}</span><span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="os" label="系统" width="140" />
        <el-table-column prop="version" label="版本" width="90">
          <template #default="{ row }">
            <span v-if="row.version">{{ row.version }}</span><span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="CPU" width="80">
          <template #default="{ row }"><span v-if="row.cpu != null">{{ formatPct(row.cpu) }}</span><span v-else>-</span></template>
        </el-table-column>
        <el-table-column label="内存" width="80">
          <template #default="{ row }"><span v-if="row.memory != null">{{ formatPct(row.memory) }}</span><span v-else>-</span></template>
        </el-table-column>
        <el-table-column label="磁盘" width="80">
          <template #default="{ row }"><span v-if="row.disk != null">{{ formatPct(row.disk) }}</span><span v-else>-</span></template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'" size="small">
              {{ row.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="mode" label="运行模式" width="100">
          <template #default="{ row }">{{ modeLabel(row.mode) }}</template>
        </el-table-column>
        <el-table-column label="告警" width="60">
          <template #default="{ row }">
            <el-badge v-if="row.alert_count > 0" :value="row.alert_count" type="danger" />
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最后心跳" width="160">
          <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.id && row.id !== 'local'" size="small" type="danger" plain @click="restartServer(row.id)" :loading="restartingId === row.id">重启</el-button>
            <el-button v-if="row.id && row.id !== 'local'" size="small" type="warning" plain @click="pauseAgent(row.id)" :loading="pausingId === row.id">暂停</el-button>
            <el-button v-if="row.id && row.id !== 'local'" size="small" type="success" plain @click="resumeAgent(row.id)" :loading="resumingId === row.id">恢复</el-button>
            <span v-if="!row.id || row.id === 'local'" style="color: #909399; font-size: 12px">本机</span>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="servers.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="servers.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>

    <!-- sgctl 快速入口提示 -->
    <el-card style="margin-top: 16px">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>命令行工具</span>
          <router-link to="/settings" style="color: #409eff; font-size: 13px">完整命令参考 →</router-link>
        </div>
      </template>
      <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: center">
        <span style="color: #64748b; font-size: 13px">常用命令：</span>
        <code class="quick-cmd">sgctl status</code>
        <code class="quick-cmd">sgctl doctor</code>
        <code class="quick-cmd">sgctl finding list</code>
        <code class="quick-cmd">sgctl emergency-stop</code>
        <code class="quick-cmd">sgctl -s http://HUB_IP:8443 status</code>
      </div>
      <div style="margin-top: 10px; color: #64748b; font-size: 12px">
        路径：<code>/opt/serverguard/sgctl</code> · 在 SSH 终端中直接使用
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'
import dayjs from 'dayjs'

const servers = ref<any[]>([])
const loading = ref(false)
const restartingId = ref('')
const pausingId = ref('')
const resumingId = ref('')
const currentPage = ref(1)
const pageSize = ref(10)
const hubMode = ref(false)

const pagedServers = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return servers.value.slice(start, start + pageSize.value)
})

async function fetchServers() {
  loading.value = true
  try {
    const resp = await axios.get('/api/servers')
    servers.value = resp.data.servers || []
    hubMode.value = !!resp.data.hub_mode
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

function modeLabel(mode: string): string {
  const labels: Record<string, string> = {
    normal: '正常运行',
    throttled: '降速运行',
    minimal: '最小运行',
    survival: '存活模式',
    emergency: '紧急模式',
  }
  return labels[mode] || mode || '-'
}

const formatPct = (v: number): string => `${Math.round(v)}%`

// 向 Hub 下发重启命令（多机集中管控）
async function restartServer(id: string) {
  restartingId.value = id
  try {
    const resp = await axios.post(`/api/servers/${encodeURIComponent(id)}/restart`)
    ElMessage.success(resp.data?.message || '重启命令已下发')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '重启命令下发失败（Agent 可能离线）')
  } finally {
    restartingId.value = ''
  }
}

// 远程暂停 Agent 自动修复
async function pauseAgent(id: string) {
  pausingId.value = id
  try {
    const resp = await axios.post(`/api/servers/${encodeURIComponent(id)}/command`, { type: 'guard.pause' })
    ElMessage.success(resp.data?.message || '暂停命令已下发')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '暂停命令下发失败')
  } finally {
    pausingId.value = ''
  }
}

// 远程恢复 Agent 自动修复
async function resumeAgent(id: string) {
  resumingId.value = id
  try {
    const resp = await axios.post(`/api/servers/${encodeURIComponent(id)}/command`, { type: 'guard.resume' })
    ElMessage.success(resp.data?.message || '恢复命令已下发')
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '恢复命令下发失败')
  } finally {
    resumingId.value = ''
  }
}

function formatTime(ts: string) {
  if (!ts) return '—'
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

onMounted(fetchServers)
</script>

<style scoped>
.quick-cmd {
  padding: 4px 10px;
  background: #f0f5ff;
  border: 1px solid #d6e1ff;
  border-radius: 6px;
  font-size: 12.5px;
  color: #409eff;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
html.dark .quick-cmd {
  background: #1d2433;
  border-color: #33415584;
  color: #60a5fa;
}
</style>
