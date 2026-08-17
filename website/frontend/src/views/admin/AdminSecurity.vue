<template>
  <div class="security-admin">
    <div class="page-card card">
      <div class="card-header">
        <h3>安全公告管理</h3>
        <el-button type="primary" @click="openEditor()">
          <el-icon><Plus /></el-icon>
          新建公告
        </el-button>
      </div>
      <el-table :data="advisories" style="width: 100%" v-loading="loading">
        <el-table-column prop="cve_id" label="CVE" width="140" />
        <el-table-column prop="title" label="标题" min-width="200" />
        <el-table-column prop="severity" label="级别" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)">
              {{ row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="patched_version" label="修复版本" width="100" />
        <el-table-column prop="published_at" label="发布时间" width="180" />
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button size="small" @click="openEditor(row)">编辑</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog
      v-model="editorVisible"
      :title="editing.id ? '编辑公告' : '新建公告'"
      width="70%"
      top="5vh"
    >
      <el-form label-position="top">
        <div class="form-row">
          <el-form-item label="CVE ID">
            <el-input v-model="editing.cve_id" placeholder="CVE-2026-XXXX" />
          </el-form-item>
          <el-form-item label="严重级别">
            <el-select v-model="editing.severity">
              <el-option label="🔴 严重" value="critical" />
              <el-option label="🟠 高危" value="high" />
              <el-option label="🟡 中危" value="medium" />
              <el-option label="🟢 低危" value="low" />
            </el-select>
          </el-form-item>
          <el-form-item label="修复版本">
            <el-input v-model="editing.patched_version" placeholder="0.1.1" />
          </el-form-item>
        </div>
        <el-form-item label="标题" required>
          <el-input v-model="editing.title" placeholder="公告标题" />
        </el-form-item>
        <el-form-item label="影响版本">
          <el-input v-model="editing.affected_versions" placeholder="0.1.0" />
        </el-form-item>
        <el-form-item label="摘要">
          <el-input v-model="editing.summary" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="详细描述（Markdown）">
          <el-input v-model="editing.description" type="textarea" :rows="10" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editorVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSave">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { adminAPI } from '@/composables/useAPI'

interface Advisory {
  id: number
  cve_id: string
  title: string
  summary: string
  description: string
  severity: string
  affected_versions: string
  patched_version: string
  published_at: string
}

const advisories = ref<Advisory[]>([])
const loading = ref(false)
const saving = ref(false)
const editorVisible = ref(false)

const editing = reactive({
  id: 0,
  cve_id: '',
  title: '',
  summary: '',
  description: '',
  severity: 'medium',
  affected_versions: '',
  patched_version: '',
})

const severityType = (sev: string) => {
  const map: Record<string, string> = {
    critical: 'danger',
    high: 'warning',
    medium: '',
    low: 'success',
  }
  return map[sev] || ''
}

const loadAdvisories = async () => {
  loading.value = true
  try {
    const resp = await adminAPI.getSecurityList()
    advisories.value = resp.data.advisories || []
  } catch {
    // API not ready
  } finally {
    loading.value = false
  }
}

const openEditor = (adv?: Advisory) => {
  if (adv) {
    Object.assign(editing, adv)
  } else {
    Object.assign(editing, {
      id: 0, cve_id: '', title: '', summary: '', description: '',
      severity: 'medium', affected_versions: '', patched_version: '',
    })
  }
  editorVisible.value = true
}

const handleSave = async () => {
  if (!editing.title) {
    ElMessage.warning('请填写标题')
    return
  }
  saving.value = true
  try {
    if (editing.id) {
      await adminAPI.updateSecurityAdvisory(editing.id, { ...editing })
      ElMessage.success('保存成功')
    } else {
      await adminAPI.createSecurityAdvisory({ ...editing })
      ElMessage.success('发布成功')
    }
    editorVisible.value = false
    loadAdvisories()
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

const handleDelete = async (adv: Advisory) => {
  try {
    await ElMessageBox.confirm(`确定删除"${adv.title}"？`, '确认', { type: 'warning' })
    await adminAPI.deleteSecurityAdvisory(adv.id)
    ElMessage.success('已删除')
    loadAdvisories()
  } catch { /* cancelled */ }
}

onMounted(loadAdvisories)
</script>

<style scoped>
.page-card { padding: 28px; }
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
</style>
