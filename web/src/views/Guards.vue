<template>
  <div>
    <el-card>
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <div style="display: flex; align-items: center; gap: 12px">
            <span>守护进程管理</span>
            <el-input v-model="searchQuery" placeholder="搜索名称/类型/命令..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
          </div>
          <el-button type="primary" @click="dialogVisible = true">添加守护</el-button>
        </div>
      </template>
      <el-alert type="info" :closable="false" style="margin-bottom: 15px">
        <template #title>什么是守护进程？</template>
        <p style="font-size: 13px; line-height: 1.8; margin: 0">
          告诉 ServerGuard 你要监控哪些服务（如 Nginx、MySQL），当服务异常时自动重启或告警。
          下面提供常用服务的预设模板，一键添加即可。
        </p>
      </el-alert>
      <el-table :data="pagedGuards" style="width: 100%" v-loading="loading">
        <el-table-column prop="name" label="名称" width="150">
          <template #default="{ row }">
            {{ row.name }}
            <el-tag v-if="row.tags && row.tags.includes('auto-detected')" size="small" type="success" style="margin-left: 5px">自动</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="120">
          <template #default="{ row }">{{ typeLabel(row.type) }}</template>
        </el-table-column>
        <el-table-column prop="command" label="启动命令" show-overflow-tooltip />
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="enabled" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '监控中' : '已暂停' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" type="warning" @click="restartGuard(row)">重启</el-button>
            <el-button size="small" type="danger" @click="deleteGuard(row)">删除</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 20px 0">
            <p style="color: #909399; margin-bottom: 15px">还没有添加任何守护进程</p>
          </div>
        </template>
      </el-table>
      <div v-if="filteredGuards.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredGuards.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>

    <el-dialog v-model="dialogVisible" title="添加守护进程" width="560px">
      <el-alert type="success" :closable="false" style="margin-bottom: 15px">
        <template #title>快速添加</template>
        <p style="font-size: 13px; margin: 5px 0">点击下方模板自动填写，然后点"添加"即可：</p>
      </el-alert>
      <div style="margin-bottom: 15px">
        <el-button v-for="tpl in templates" :key="tpl.name" size="small" @click="applyTemplate(tpl)">
          {{ tpl.name }}
        </el-button>
      </div>
      <el-form :model="newGuard" label-width="80px">
        <el-form-item label="名称"><el-input v-model="newGuard.name" placeholder="如：Nginx" /></el-form-item>
        <el-form-item label="类型">
          <el-select v-model="newGuard.type" style="width: 100%">
            <el-option label="裸进程（直接运行的程序）" value="bare_process" />
            <el-option label="Systemd 服务（Linux）" value="systemd" />
            <el-option label="Docker 容器" value="docker" />
            <el-option label="端口监听（只检查端口）" value="port" />
            <el-option label="Windows 服务" value="windows_service" />
          </el-select>
        </el-form-item>
        <el-form-item label="启动命令"><el-input v-model="newGuard.command" placeholder="如：nginx -g 'daemon off;'" /></el-form-item>
        <el-form-item label="进程名"><el-input v-model="newGuard.process_name" placeholder="如：nginx（用于查找进程）" /></el-form-item>
        <el-form-item label="端口"><el-input-number v-model="newGuard.port" :min="0" :max="65535" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="addGuard" :loading="adding">添加</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, reactive } from 'vue'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'

const guards = ref<any[]>([])
const loading = ref(false)
const dialogVisible = ref(false)
const adding = ref(false)
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const filteredGuards = computed(() => {
  if (!searchQuery.value) return guards.value
  const q = searchQuery.value.toLowerCase()
  return guards.value.filter((g: any) =>
    g.name?.toLowerCase().includes(q) ||
    g.type?.toLowerCase().includes(q) ||
    g.command?.toLowerCase().includes(q)
  )
})
const pagedGuards = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredGuards.value.slice(start, start + pageSize.value)
})
const newGuard = reactive({
  name: '', type: 'bare_process', command: '', process_name: '', port: 0
})

const templates = [
  { name: 'Nginx', data: { name: 'Nginx', type: 'bare_process', command: 'nginx', process_name: 'nginx', port: 80 } },
  { name: 'MySQL', data: { name: 'MySQL', type: 'bare_process', command: 'mysqld', process_name: 'mysqld', port: 3306 } },
  { name: 'Redis', data: { name: 'Redis', type: 'bare_process', command: 'redis-server', process_name: 'redis-server', port: 6379 } },
  { name: 'SSH', data: { name: 'SSH', type: 'bare_process', command: '/usr/sbin/sshd', process_name: 'sshd', port: 22 } },
  { name: 'IIS', data: { name: 'IIS', type: 'windows_service', command: 'iisreset /start', process_name: 'w3svc', port: 80 } },
  { name: 'PHP-FPM', data: { name: 'PHP-FPM', type: 'bare_process', command: 'php-fpm', process_name: 'php-fpm', port: 9000 } },
  { name: 'PostgreSQL', data: { name: 'PostgreSQL', type: 'bare_process', command: 'postgres', process_name: 'postgres', port: 5432 } },
  { name: 'MongoDB', data: { name: 'MongoDB', type: 'bare_process', command: 'mongod', process_name: 'mongod', port: 27017 } },
  { name: '自定义', data: { name: '', type: 'bare_process', command: '', process_name: '', port: 0 } },
]

function applyTemplate(tpl: any) {
  Object.assign(newGuard, tpl.data)
}

async function fetchGuards() {
  loading.value = true
  try {
    const resp = await axios.get('/api/guards')
    guards.value = resp.data.guards || []
  } catch (err) {
    // ignore
  } finally {
    loading.value = false
  }
}

async function addGuard() {
  if (!newGuard.name) {
    ElMessage.warning('请输入名称')
    return
  }
  adding.value = true
  try {
    await axios.post('/api/guards', newGuard)
    ElMessage.success('守护进程已添加')
    dialogVisible.value = false
    Object.assign(newGuard, { name: '', type: 'bare_process', command: '', process_name: '', port: 0 })
    fetchGuards()
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '添加失败')
  } finally {
    adding.value = false
  }
}

async function deleteGuard(row: any) {
try {
  await ElMessageBox.confirm(
    `确认删除守护目标 "${row.name}" 吗？删除后该服务将不再被自动守护。`,
    '删除确认',
    { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' }
  )
} catch { return }
try {
await axios.delete(`/api/guards/${row.id}`)
ElMessage.success('已删除')
    fetchGuards()
  } catch (err) {
    ElMessage.error('删除失败')
  }
}

async function restartGuard(row: any) {
try {
  await ElMessageBox.confirm(
    `确认重启 "${row.name}" 吗？该服务将短暂中断。`,
    '重启确认',
    { confirmButtonText: '重启', cancelButtonText: '取消', type: 'warning' }
  )
} catch { return }
ElMessage.info(`正在重启 ${row.name}...`)
  try {
    await axios.post(`/api/servers/local/restart`, { target: row.id })
    ElMessage.success(`${row.name} 重启指令已发送`)
  } catch (err) {
    ElMessage.error('重启失败，请手动检查')
  }
}

function typeLabel(type: string): string {
  const labels: Record<string, string> = {
    bare_process: '裸进程',
    systemd: 'Systemd 服务',
    docker: 'Docker 容器',
    port: '端口监听',
    windows_service: 'Windows 服务',
  }
  return labels[type] || type
}

onMounted(fetchGuards)
</script>
