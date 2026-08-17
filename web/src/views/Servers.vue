<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>服务器列表</span>
          <el-button text @click="fetchServers">刷新</el-button>
        </div>
      </template>
      <el-table :data="pagedServers" v-loading="loading">
        <el-table-column prop="hostname" label="主机名" />
        <el-table-column prop="ip" label="IP 地址" width="150" />
        <el-table-column prop="id" label="Agent ID" width="170" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.id">{{ row.id }}</span><span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column prop="os" label="系统" width="150" />
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
            <el-tag :type="row.status === 'online' ? 'success' : 'danger'">
              {{ row.status === 'online' ? '在线' : '离线' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="mode" label="运行模式" width="100">
          <template #default="{ row }">{{ modeLabel(row.mode) }}</template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最后心跳" width="180">
          <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.id" size="small" type="danger" plain @click="restartServer(row.id)" :loading="restartingId === row.id">重启</el-button>
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
const currentPage = ref(1)
const pageSize = ref(10)

const pagedServers = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return servers.value.slice(start, start + pageSize.value)
})

async function fetchServers() {
  loading.value = true
  try {
    const resp = await axios.get('/api/servers')
    servers.value = resp.data.servers || []
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
  return labels[mode] || mode
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

function formatTime(ts: string) {
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss')
}

onMounted(fetchServers)
</script>
