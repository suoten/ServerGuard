<template>
  <div class="config-approval">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>配置变更历史</span>
          <el-button @click="loadVersions">刷新</el-button>
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 15px">
        <template #title>什么是配置变更历史？</template>
        <p style="font-size: 13px; line-height: 1.8; margin: 0">
          ServerGuard 每次修改服务器配置（如 sshd_config、sysctl 等）时，会自动保存一个版本快照。
          你可以在这里查看每次变更的内容、回滚到之前的版本，确保配置修改不会导致服务器故障。
          <strong>如果你没有手动修改过配置，这里可能为空，这是正常的。</strong>
        </p>
      </el-alert>

      <el-table :data="pagedVersions" stripe v-loading="loading">
        <el-table-column prop="commit_id" label="版本号" width="150" />
        <el-table-column prop="file_path" label="修改的文件" width="200" />
        <el-table-column prop="author" label="修改者" width="100" />
        <el-table-column prop="message" label="变更说明" />
        <el-table-column prop="is_approved" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.is_approved ? 'success' : 'warning'">
              {{ row.is_approved ? '已确认' : '待确认' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="时间" width="180" />
        <el-table-column label="操作" width="250">
          <template #default="{ row }">
            <el-button size="small" @click="viewDiff(row)">查看变更</el-button>
            <el-button size="small" type="success" v-if="!row.is_approved" @click="approve(row)">确认</el-button>
            <el-button size="small" type="warning" @click="rollback(row)">回滚到此版本</el-button>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 20px 0">
            <p style="color: #909399">暂无配置变更记录</p>
            <p style="color: #c0c4cc; font-size: 13px">当 ServerGuard 自动修改服务器配置时，变更记录会显示在这里</p>
          </div>
        </template>
      </el-table>
      <div v-if="versions.length > 10" style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="versions.length"
          layout="total, sizes, prev, pager, next"
        />
      </div>
    </el-card>

    <el-dialog v-model="showDiff" title="配置变更内容" width="80%">
      <pre class="diff-content">{{ currentDiff }}</pre>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import axios from 'axios'

const versions = ref([])
const loading = ref(false)
const showDiff = ref(false)
const currentDiff = ref('')
const currentPage = ref(1)
const pageSize = ref(10)

const pagedVersions = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return versions.value.slice(start, start + pageSize.value)
})

async function loadVersions() {
  loading.value = true
  try {
    const resp = await axios.get('/api/config-versions', { params: { limit: 50 } })
    versions.value = resp.data.versions || []
  } catch {
    ElMessage.error('加载版本列表失败')
  } finally {
    loading.value = false
  }
}

function viewDiff(row) {
  currentDiff.value = row.diff || '无变更内容'
  showDiff.value = true
}

async function approve(row) {
  try {
    await ElMessageBox.confirm(`确认这个配置变更 ${row.commit_id}?`, '确认变更', { type: 'info' })
    const resp = await axios.post(`/api/config-versions/${row.commit_id}/approve`)
    if (resp.status === 200) {
      ElMessage.success('已确认')
      loadVersions()
    }
  } catch {}
}

async function rollback(row) {
  try {
    await ElMessageBox.confirm(
      `确认回滚到版本 ${row.commit_id}?\n此操作将覆盖当前配置文件，可能会影响服务运行。`,
      '配置回滚',
      { type: 'warning' }
    )
    const resp = await axios.post(`/api/config-versions/${row.commit_id}/rollback`)
    if (resp.status === 200) {
      ElMessage.success('回滚成功')
    }
  } catch {}
}

loadVersions()
</script>

<style scoped>
.config-approval { padding: 20px; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.diff-content { background: #1e1e1e; color: #d4d4d4; padding: 16px; border-radius: 4px; overflow: auto; max-height: 500px; }
</style>
