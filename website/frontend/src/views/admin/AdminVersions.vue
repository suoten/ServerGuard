<template>
  <div class="versions-admin">
    <!-- Upload New Version -->
    <div class="page-card card">
      <div class="card-header">
        <h3>上传新版本</h3>
      </div>
      <el-alert
        title="版本更新机制"
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 24px"
      >
        <template #default>
          上传新版本后，Agent 通过 <code>/api/v1/latest</code> 接口自动检测。
          版本号需大于当前版本才会提示用户升级（语义化版本比较）。
        </template>
      </el-alert>
      <el-form label-position="top" class="upload-form">
        <div class="form-row">
          <el-form-item label="版本号" required>
            <el-input v-model="newVersion.version" placeholder="0.1.1" />
          </el-form-item>
          <el-form-item label="渠道">
            <el-select v-model="newVersion.channel" style="width: 100%">
              <el-option label="stable（稳定版）" value="stable" />
              <el-option label="beta（测试版）" value="beta" />
              <el-option label="edge（开发版）" value="edge" />
            </el-select>
          </el-form-item>
          <el-form-item label="是否关键更新">
            <el-switch v-model="newVersion.critical" />
            <span class="hint">关键更新会强制提示用户升级</span>
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="操作系统" required>
            <el-select v-model="newVersion.os" style="width: 100%">
              <el-option label="Linux" value="linux" />
              <el-option label="Windows" value="windows" />
              <el-option label="macOS" value="darwin" />
            </el-select>
          </el-form-item>
          <el-form-item label="架构" required>
            <el-select v-model="newVersion.arch" style="width: 100%">
              <el-option label="amd64（x86_64）" value="amd64" />
              <el-option label="arm64（aarch64）" value="arm64" />
            </el-select>
          </el-form-item>
          <el-form-item label="说明">
            <span class="hint" style="margin-left: 0">同一版本需分平台各上传一次，Agent 按 os/arch 精确匹配更新包</span>
          </el-form-item>
        </div>
        <el-form-item label="更新日志" required>
          <el-input
            v-model="newVersion.release_notes"
            type="textarea"
            :rows="4"
            placeholder="## v0.1.1&#10;&#10;- 修复 xxx 问题&#10;- 新增 xxx 功能&#10;- 优化 xxx 性能"
          />
        </el-form-item>
        <div class="upload-area">
          <el-upload
            ref="uploadRef"
            :auto-upload="false"
            :limit="1"
            drag
            :on-change="handleFileChange"
            :file-list="fileList"
          >
            <el-icon class="upload-icon"><UploadFilled /></el-icon>
            <div class="upload-text">拖拽二进制文件到此处，或点击选择</div>
            <div class="upload-hint">Linux 无扩展名二进制 / Windows .exe</div>
          </el-upload>
        </div>
        <div class="upload-actions">
          <el-button type="primary" size="large" :loading="uploading" @click="handleUpload">
            <el-icon><Upload /></el-icon>
            发布版本
          </el-button>
        </div>
      </el-form>
    </div>

    <!-- Version List -->
    <div class="page-card card">
      <div class="card-header">
        <h3>已发布版本</h3>
        <el-button @click="loadVersions" :icon="Refresh">刷新</el-button>
      </div>
      <el-table :data="versions" style="width: 100%" v-loading="loading">
        <el-table-column prop="version" label="版本号" width="100" />
        <el-table-column label="平台" width="130">
          <template #default="{ row }">
            <el-tag effect="plain">{{ row.os }}/{{ row.arch }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="channel" label="渠道" width="100">
          <template #default="{ row }">
            <el-tag :type="row.channel === 'stable' ? 'success' : 'warning'">
              {{ row.channel }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="100">
          <template #default="{ row }">
            {{ formatSize(row.file_size) }}
          </template>
        </el-table-column>
        <el-table-column label="SHA256" min-width="140">
          <template #default="{ row }">
            <code class="sha-cell" :title="row.sha256">{{ row.sha256 }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="downloads" label="下载量" width="90" />
        <el-table-column prop="created_at" label="发布时间" width="170" />
        <el-table-column prop="critical" label="关键" width="70">
          <template #default="{ row }">
            <el-tag v-if="row.critical" type="danger">关键</el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="170" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="toggleStatus(row)">
              {{ row.enabled ? '隐藏' : '显示' }}
            </el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Upload, Refresh } from '@element-plus/icons-vue'
import { adminAPI } from '@/composables/useAPI'
import type { UploadFile } from 'element-plus'

interface Version {
  id: number
  version: string
  channel: string
  os: string
  arch: string
  downloads: number
  critical: boolean
  enabled: boolean
  created_at: string
  release_notes: string
  sha256: string
  file_size: number
}

const versions = ref<Version[]>([])
const loading = ref(false)
const uploading = ref(false)
const fileList = ref<UploadFile[]>([])

const newVersion = reactive({
  version: '',
  channel: 'stable',
  os: 'linux',
  arch: 'amd64',
  critical: false,
  release_notes: '',
})

const selectedFile = ref<File | null>(null)

const loadVersions = async () => {
  loading.value = true
  try {
    const resp = await adminAPI.getVersions()
    versions.value = resp.data.versions || []
  } catch {
    // API not ready
  } finally {
    loading.value = false
  }
}

const handleFileChange = (file: UploadFile) => {
  if (file.raw) {
    selectedFile.value = file.raw
  }
}

const handleUpload = async () => {
  if (!newVersion.version) {
    ElMessage.warning('请输入版本号')
    return
  }
  if (!newVersion.release_notes) {
    ElMessage.warning('请填写更新日志')
    return
  }
  if (!selectedFile.value) {
    ElMessage.warning('请选择二进制文件')
    return
  }

  uploading.value = true
  try {
    const formData = new FormData()
    formData.append('version', newVersion.version)
    formData.append('channel', newVersion.channel)
    formData.append('os', newVersion.os)
    formData.append('arch', newVersion.arch)
    formData.append('critical', String(newVersion.critical))
    formData.append('release_notes', newVersion.release_notes)
    formData.append('file', selectedFile.value)

    await adminAPI.createVersion(formData)
    ElMessage.success(`版本 v${newVersion.version} (${newVersion.os}/${newVersion.arch}) 发布成功！Agent 端将自动检测到此更新。`)
    
    // Reset form
    newVersion.version = ''
    newVersion.critical = false
    newVersion.release_notes = ''
    selectedFile.value = null
    fileList.value = []
    
    loadVersions()
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '发布失败')
  } finally {
    uploading.value = false
  }
}

const formatSize = (bytes: number) => {
  if (!bytes) return '—'
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${Math.round(bytes / 1024)} KB`
}

const toggleStatus = async (row: Version) => {
  try {
    await adminAPI.updateVersion(row.id, { enabled: !row.enabled })
    row.enabled = !row.enabled
    ElMessage.success(row.enabled ? '已显示' : '已隐藏')
  } catch (err: any) {
    ElMessage.error('操作失败')
  }
}

const handleDelete = async (row: Version) => {
  try {
    await ElMessageBox.confirm(`确定删除版本 v${row.version}？此操作不可恢复。`, '确认删除', {
      type: 'warning',
    })
    await adminAPI.deleteVersion(row.id)
    ElMessage.success('已删除')
    loadVersions()
  } catch {
    // Cancelled
  }
}

onMounted(loadVersions)
</script>

<style scoped>
.page-card { padding: 28px; margin-bottom: 24px; }
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}
.card-header h3 { font-size: 18px; }
.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 16px;
}
.upload-area { margin: 16px 0; }
.upload-icon { font-size: 48px; color: var(--text-muted); }
.upload-text { color: var(--text-secondary); margin-top: 8px; }
.upload-hint { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
.upload-actions { text-align: center; padding: 16px 0; }
.hint { margin-left: 8px; color: var(--text-muted); font-size: 13px; }
.sha-cell {
  font-family: monospace;
  font-size: 11px;
  color: var(--text-muted);
  display: inline-block;
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: middle;
}
</style>
