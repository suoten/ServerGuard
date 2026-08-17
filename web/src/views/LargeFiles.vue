<template>
  <div class="large-files-page">
    <!-- 快捷删除卡片 -->
    <el-card v-if="quickCategories.length > 0" style="margin-bottom: 15px">
      <template #header>
        <div class="card-header">
          <span>快捷清理 <el-tag size="small" type="success">点击查看详情并选择删除</el-tag></span>
          <el-button type="primary" size="small" @click="loadQuickCategories" :loading="loadingCategories">刷新分类</el-button>
        </div>
      </template>
      <div class="quick-categories">
        <div
          v-for="cat in quickCategories"
          :key="cat.id"
          class="quick-cat-card"
          @click="showCategoryFiles(cat)"
        >
          <div class="quick-cat-info">
            <div class="quick-cat-name">{{ cat.name }}</div>
            <div class="quick-cat-desc">{{ cat.description }}</div>
            <div class="quick-cat-stats">
              <el-tag size="small" type="warning">{{ cat.count }} 个文件</el-tag>
              <el-tag size="small" type="danger">{{ formatSize(cat.size_mb) }}</el-tag>
            </div>
          </div>
          <el-button type="danger" size="small" plain>查看详情</el-button>
        </div>
      </div>
    </el-card>

    <!-- 大文件列表 -->
    <el-card>
      <template #header>
        <div class="card-header">
          <span>大文件扫描
            <el-tag size="small" type="info">共 {{ total }} 个文件</el-tag>
            <el-tag v-if="deletableCount > 0" size="small" type="success" style="margin-left: 5px">
              {{ deletableCount }} 个可删除（{{ formatSize(deletableSizeMB) }}）
            </el-tag>
          </span>
          <div class="header-actions">
            <el-input
              v-model="searchQuery"
              placeholder="搜索文件路径/名称..."
              size="small"
              clearable
              style="width: 220px"
              :prefix-icon="Search"
            />
            <el-select v-model="filterSize" placeholder="最小大小" size="small" style="width: 120px" @change="onFilterChange">
              <el-option label="≥ 50MB" value="50" />
              <el-option label="≥ 100MB" value="100" />
              <el-option label="≥ 500MB" value="500" />
              <el-option label="≥ 1GB" value="1024" />
            </el-select>
            <el-select v-model="filterType" placeholder="文件类型" size="small" clearable style="width: 130px">
              <el-option label="日志" value="log" />
              <el-option label="压缩/归档" value="archive" />
              <el-option label="共享库" value="library" />
              <el-option label="Python 包" value="python_package" />
              <el-option label="Node.js 包" value="node_package" />
              <el-option label="数据库" value="database" />
              <el-option label="临时/缓存" value="cache" />
              <el-option label="模型文件" value="model" />
              <el-option label="可执行文件" value="binary" />
              <el-option label="其他" value="other" />
            </el-select>
            <el-select v-model="filterDeletable" placeholder="可删除" size="small" clearable style="width: 110px">
              <el-option label="仅可删除" value="yes" />
              <el-option label="仅不可删除" value="no" />
            </el-select>
            <el-button v-if="selectedFiles.length > 0" type="danger" size="small" @click="batchDelete">
              批量删除（{{ selectedFiles.length }}）
            </el-button>
            <el-button type="primary" size="small" @click="scanFiles" :loading="scanning">重新扫描</el-button>
          </div>
        </div>
      </template>

      <el-alert type="info" :closable="false" show-icon style="margin-bottom: 15px">
        扫描系统中占用磁盘空间较大的文件。<strong>可删除</strong>的文件会显示删除按钮（日志、缓存、临时文件等），<strong>不可删除</strong>的文件（系统库、Python包、数据库文件等）不提供删除按钮，防止误删导致业务异常。
      </el-alert>

      <el-table
        :data="pagedFiles"
        stripe
        v-loading="scanning"
        style="width: 100%"
        @selection-change="handleSelectionChange"
        :row-key="(row: any) => row.path"
      >
        <el-table-column type="selection" width="45" :selectable="(row: any) => row.can_delete" />
        <el-table-column prop="path" label="文件路径" min-width="400" show-overflow-tooltip />
        <el-table-column prop="size_mb" label="大小" width="120" sortable>
          <template #default="{ row }">
            <el-tag :type="sizeTagType(row.size_mb)" size="small">{{ formatSize(row.size_mb) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="file_type" label="类型" width="110">
          <template #default="{ row }">
            <el-tag :type="fileTypeTagType(row.file_type)" size="small">{{ fileTypeLabel(row.file_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="owner" label="所有者" width="90">
          <template #default="{ row }">{{ row.owner || '-' }}</template>
        </el-table-column>
        <el-table-column prop="mod_time" label="修改时间" width="160">
          <template #default="{ row }">{{ formatTime(row.mod_time) }}</template>
        </el-table-column>
        <el-table-column prop="can_delete" label="可删除" width="220">
          <template #default="{ row }">
            <el-tooltip :content="row.delete_hint" placement="top">
              <el-tag :type="row.can_delete ? 'success' : 'info'" size="small">
                {{ row.can_delete ? '可删除' : '不可删除' }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.can_delete"
              size="small"
              type="danger"
              @click="deleteFile(row)"
              :loading="deletingPath === row.path"
            >删除</el-button>
            <span v-else style="color: #c0c4cc; font-size: 12px">—</span>
          </template>
        </el-table-column>
        <template #empty>
          <div style="padding: 30px 0; text-align: center">
            <el-icon style="font-size: 32px; color: #c0c4cc; margin-bottom: 10px"><FolderOpened /></el-icon>
            <p style="color: #909399; margin: 0">点击"重新扫描"查找系统中的大文件</p>
            <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">扫描完成后将按大小降序显示</p>
          </div>
        </template>
      </el-table>

      <div style="margin-top: 16px; display: flex; justify-content: flex-end" v-if="total > 0">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <!-- 分类文件详情对话框 -->
    <el-dialog
      v-model="categoryDialogVisible"
      :title="`快捷清理 - ${currentCategoryName}`"
      width="900px"
      top="5vh"
    >
      <div v-loading="loadingCategoryFiles">
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 15px">
          请确认下方文件列表，取消勾选不需要删除的文件，然后点击「确认清理」按钮。
        </el-alert>

        <div style="margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center">
          <span>
            <el-checkbox v-model="selectAllFiles" @change="toggleSelectAll">全选</el-checkbox>
            <span style="margin-left: 15px; color: #606266">
              已选 <strong style="color: #f56c6c">{{ selectedCategoryFiles.length }}</strong> / {{ categoryFileList.length }} 个文件
              <span v-if="selectedCategoryFiles.length > 0">
                ，共 <strong style="color: #f56c6c">{{ formatSize(selectedCategorySize) }}</strong>
              </span>
            </span>
          </span>
          <el-button type="danger" size="small" :disabled="selectedCategoryFiles.length === 0" @click="confirmQuickDelete">
            确认清理（{{ selectedCategoryFiles.length }} 个文件）
          </el-button>
        </div>

        <el-table
          :data="categoryFileList"
          stripe
          max-height="500"
          style="width: 100%"
          @selection-change="handleCategorySelectionChange"
          :row-key="(row: any) => row.path"
          ref="categoryTableRef"
        >
          <el-table-column type="selection" width="45" />
          <el-table-column prop="path" label="文件路径" min-width="350" show-overflow-tooltip />
          <el-table-column prop="size_mb" label="大小" width="110" sortable>
            <template #default="{ row }">
              <el-tag :type="sizeTagType(row.size_mb)" size="small">{{ formatSize(row.size_mb) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="mod_time" label="修改时间" width="150">
            <template #default="{ row }">{{ formatTime(row.mod_time) }}</template>
          </el-table-column>
          <el-table-column prop="delete_hint" label="说明" min-width="150" show-overflow-tooltip />
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { TableInstance } from 'element-plus'
import { Search, FolderOpened } from '@element-plus/icons-vue'
import axios from 'axios'
import dayjs from 'dayjs'

interface LargeFile {
  path: string
  size: number
  size_mb: number
  mod_time: string
  owner: string
  is_dir: boolean
  can_delete: boolean
  delete_hint: string
  file_type: string
}

interface QuickCategory {
  id: string
  name: string
  description: string
  path_pattern?: string
  count: number
  size_mb: number
}

const files = ref<LargeFile[]>([])
const quickCategories = ref<QuickCategory[]>([])
const scanning = ref(false)
const deletingPath = ref('')
const loadingCategories = ref(false)
const batchDeleting = ref(false)
const searchQuery = ref('')
const filterSize = ref('100')
const filterType = ref('')
const filterDeletable = ref('')
const currentPage = ref(1)
const pageSize = ref(20)
const selectedFiles = ref<LargeFile[]>([])
const deletableCount = ref(0)
const deletableSizeMB = ref(0)

// 分类文件对话框状态
const categoryDialogVisible = ref(false)
const currentCategoryName = ref('')
const currentCategoryId = ref('')
const categoryFileList = ref<LargeFile[]>([])
const selectedCategoryFiles = ref<LargeFile[]>([])
const loadingCategoryFiles = ref(false)
const selectAllFiles = ref(true)
const categoryTableRef = ref<TableInstance>()

const filteredFiles = computed(() => {
  let result = files.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(f =>
      f.path?.toLowerCase().includes(q) ||
      f.owner?.toLowerCase().includes(q)
    )
  }
  if (filterType.value) {
    result = result.filter(f => f.file_type === filterType.value)
  }
  if (filterDeletable.value === 'yes') {
    result = result.filter(f => f.can_delete)
  } else if (filterDeletable.value === 'no') {
    result = result.filter(f => !f.can_delete)
  }
  return result
})

const total = computed(() => filteredFiles.value.length)

const pagedFiles = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredFiles.value.slice(start, start + pageSize.value)
})

const selectedCategorySize = computed(() => {
  return selectedCategoryFiles.value.reduce((sum, f) => sum + f.size_mb, 0)
})

const onFilterChange = () => {
  currentPage.value = 1
  scanFiles()
}

const formatSize = (mb: number) => {
  if (!mb || mb === 0) return '0 MB'
  if (mb >= 1024) return (mb / 1024).toFixed(2) + ' GB'
  return mb.toFixed(1) + ' MB'
}

const sizeTagType = (mb: number) => {
  if (mb >= 1024) return 'danger'
  if (mb >= 500) return 'warning'
  if (mb >= 200) return 'primary'
  return 'info'
}

const fileTypeLabel = (type: string) => {
  const labels: Record<string, string> = {
    log: '日志',
    archive: '压缩包',
    library: '共享库',
    python_package: 'Python包',
    node_package: 'Node包',
    database: '数据库',
    cache: '临时/缓存',
    model: '模型',
    binary: '可执行',
    image: '镜像',
    video: '视频',
    other: '其他',
  }
  return labels[type] || type
}

const fileTypeTagType = (type: string) => {
  const types: Record<string, string> = {
    log: 'success',
    archive: 'warning',
    library: 'danger',
    python_package: 'danger',
    node_package: 'danger',
    database: 'danger',
    cache: 'success',
    model: 'warning',
    binary: 'danger',
    image: 'info',
    video: 'info',
    other: 'info',
  }
  return types[type] || 'info'
}

const formatTime = (ts: string) => {
  if (!ts || ts === '0001-01-01T00:00:00Z') return '-'
  return dayjs(ts).format('YYYY-MM-DD HH:mm')
}

const handleSelectionChange = (selection: LargeFile[]) => {
  selectedFiles.value = selection
}

async function scanFiles() {
  scanning.value = true
  try {
    const resp = await axios.get('/api/large-files', { params: { min_size_mb: filterSize.value } })
    files.value = resp.data.files || []
    deletableCount.value = resp.data.deletable_count || 0
    deletableSizeMB.value = resp.data.deletable_size_mb || 0
    currentPage.value = 1
    if (files.value.length > 0) {
      ElMessage.success(`发现 ${files.value.length} 个大文件，其中 ${deletableCount.value} 个可删除`)
    } else {
      ElMessage.info('未发现大文件')
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '扫描失败')
  } finally {
    scanning.value = false
  }
}

async function loadQuickCategories() {
  loadingCategories.value = true
  try {
    const resp = await axios.get('/api/large-files/quick-categories', { params: { min_size_mb: filterSize.value } })
    quickCategories.value = resp.data.categories || []
  } catch (e: any) {
    // 静默处理
  } finally {
    loadingCategories.value = false
  }
}

async function deleteFile(row: LargeFile) {
  try {
    await ElMessageBox.confirm(
      `确认删除文件：${row.path}（${formatSize(row.size_mb)}）？\n\n${row.delete_hint}\n\n此操作不可逆！`,
      '删除大文件',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
    )
  } catch {
    return
  }

  deletingPath.value = row.path
  try {
    await axios.post('/api/large-files/delete', { path: row.path })
    ElMessage.success(`已删除 ${formatSize(row.size_mb)}`)
    files.value = files.value.filter((f: any) => f.path !== row.path)
    deletableCount.value = Math.max(0, deletableCount.value - 1)
    deletableSizeMB.value = Math.max(0, deletableSizeMB.value - row.size_mb)
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '删除失败')
  } finally {
    deletingPath.value = ''
  }
}

async function batchDelete() {
  if (selectedFiles.value.length === 0) return
  const totalSize = selectedFiles.value.reduce((sum, f) => sum + f.size_mb, 0)
  try {
    await ElMessageBox.confirm(
      `确认批量删除 ${selectedFiles.value.length} 个文件（共 ${formatSize(totalSize)}）？\n\n此操作不可逆！`,
      '批量删除',
      { type: 'warning', confirmButtonText: '确认删除', cancelButtonText: '取消' }
    )
  } catch {
    return
  }

  batchDeleting.value = true
  try {
    const paths = selectedFiles.value.map(f => f.path)
    const resp = await axios.post('/api/large-files/batch-delete', { paths })
    const data = resp.data
    ElMessage.success(data.message || `已删除 ${data.deleted_count} 个文件`)

    // 从列表中移除已删除的文件
    const deletedPaths = new Set((data.deleted || []).map((d: any) => d.path))
    files.value = files.value.filter((f: any) => !deletedPaths.has(f.path))
    deletableCount.value = Math.max(0, deletableCount.value - (data.deleted_count || 0))
    deletableSizeMB.value = Math.max(0, deletableSizeMB.value - (data.total_saved_mb || 0))
    selectedFiles.value = []

    if (data.failed_count > 0) {
      ElMessage.warning(`${data.failed_count} 个文件删除失败`)
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '批量删除失败')
  } finally {
    batchDeleting.value = false
  }
}

// ─── 分类文件详情对话框 ───

async function showCategoryFiles(cat: QuickCategory) {
  currentCategoryId.value = cat.id
  currentCategoryName.value = cat.name
  categoryDialogVisible.value = true
  loadingCategoryFiles.value = true
  selectAllFiles.value = true

  try {
    const resp = await axios.get(`/api/large-files/quick-categories/${cat.id}/files`, {
      params: { min_size_mb: filterSize.value }
    })
    categoryFileList.value = resp.data.files || []

    // 默认全选
    await nextTick()
    if (categoryTableRef.value) {
      categoryTableList.value.forEach(row => {
        categoryTableRef.value?.toggleRowSelection(row, true)
      })
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '获取文件列表失败')
    categoryFileList.value = []
  } finally {
    loadingCategoryFiles.value = false
  }
}

// 用于全选操作的引用
const categoryTableList = computed(() => categoryFileList.value)

function handleCategorySelectionChange(selection: LargeFile[]) {
  selectedCategoryFiles.value = selection
  selectAllFiles.value = selection.length === categoryFileList.value.length
}

async function toggleSelectAll(val: any) {
  await nextTick()
  if (categoryTableRef.value) {
    if (val) {
      categoryFileList.value.forEach(row => {
        categoryTableRef.value?.toggleRowSelection(row, true)
      })
    } else {
      categoryTableRef.value?.clearSelection()
    }
  }
}

async function confirmQuickDelete() {
  if (selectedCategoryFiles.value.length === 0) {
    ElMessage.warning('请至少选择一个文件')
    return
  }

  const totalSize = selectedCategoryFiles.value.reduce((sum, f) => sum + f.size_mb, 0)
  try {
    await ElMessageBox.confirm(
      `确认清理 ${selectedCategoryFiles.value.length} 个文件（共 ${formatSize(totalSize)}）？\n\n此操作不可逆！`,
      '快捷清理确认',
      { type: 'warning', confirmButtonText: '确认清理', cancelButtonText: '取消' }
    )
  } catch {
    return
  }

  try {
    const paths = selectedCategoryFiles.value.map(f => f.path)
    const resp = await axios.post('/api/large-files/batch-delete', { paths })
    const data = resp.data
    ElMessage.success(data.message || `已删除 ${data.deleted_count} 个文件`)

    categoryDialogVisible.value = false

    // 刷新列表
    await scanFiles()
    await loadQuickCategories()

    if (data.failed_count > 0) {
      ElMessage.warning(`${data.failed_count} 个文件删除失败`)
    }
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '快捷清理失败')
  }
}

onMounted(() => {
  scanFiles()
  loadQuickCategories()
})
</script>

<style scoped>
.large-files-page { width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }

.quick-categories {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
.quick-cat-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
  min-width: 240px;
}
.quick-cat-card:hover {
  border-color: #f56c6c;
  box-shadow: 0 2px 8px rgba(245, 108, 108, 0.15);
}
.quick-cat-info {
  flex: 1;
}
.quick-cat-name {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 4px;
}
.quick-cat-desc {
  font-size: 12px;
  color: #909399;
  margin-bottom: 6px;
}
.quick-cat-stats {
  display: flex;
  gap: 6px;
}
</style>
