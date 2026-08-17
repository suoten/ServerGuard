<template>
  <div class="blog-admin">
    <!-- Blog List -->
    <div class="page-card card">
      <div class="card-header">
        <h3>博客文章</h3>
        <el-button type="primary" @click="openEditor()">
          <el-icon><Plus /></el-icon>
          写文章
        </el-button>
      </div>
      <el-table :data="posts" style="width: 100%" v-loading="loading">
        <el-table-column prop="title" label="标题" min-width="200" />
        <el-table-column prop="category" label="分类" width="120" />
        <el-table-column prop="author" label="作者" width="100" />
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'published' ? 'success' : 'info'">
              {{ row.status === 'published' ? '已发布' : '草稿' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180" />
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button size="small" @click="openEditor(row)">编辑</el-button>
            <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Editor Dialog -->
    <el-dialog
      v-model="editorVisible"
      :title="editing.id ? '编辑文章' : '写文章'"
      width="80%"
      top="5vh"
      class="blog-editor-dialog"
    >
      <el-form label-position="top" class="blog-form">
        <div class="form-row">
          <el-form-item label="标题" required>
            <el-input v-model="editing.title" placeholder="文章标题" />
          </el-form-item>
          <el-form-item label="分类">
            <el-input v-model="editing.category" placeholder="技术分享" />
          </el-form-item>
        </div>
        <div class="form-row">
          <el-form-item label="Slug（URL路径）">
            <el-input v-model="editing.slug" placeholder="my-first-post" />
          </el-form-item>
          <el-form-item label="作者">
            <el-input v-model="editing.author" placeholder="作者名" />
          </el-form-item>
          <el-form-item label="状态">
            <el-select v-model="editing.status">
              <el-option label="草稿" value="draft" />
              <el-option label="已发布" value="published" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="摘要">
          <el-input v-model="editing.excerpt" type="textarea" :rows="2" placeholder="一句话摘要" />
        </el-form-item>
        <el-form-item label="正文（Markdown）" required>
          <MdEditor
            v-model="editing.content"
            :style="{ height: '500px', width: '100%' }"
            :toolbarsExclude="['github', 'save', 'pageFullscreen', 'catalog']"
            language="zh-CN"
            :dark="true"
            placeholder="支持 Markdown 格式..."
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editorVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSave">
          {{ editing.id ? '保存修改' : '发布' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { MdEditor } from 'md-editor-v3'
import 'md-editor-v3/lib/style.css'
import { adminAPI } from '@/composables/useAPI'

interface BlogPost {
  id: number
  title: string
  slug: string
  excerpt: string
  content: string
  author: string
  category: string
  status: string
  created_at: string
}

const posts = ref<BlogPost[]>([])
const loading = ref(false)
const saving = ref(false)
const editorVisible = ref(false)

const editing = reactive({
  id: 0,
  title: '',
  slug: '',
  excerpt: '',
  content: '',
  author: '',
  category: '',
  status: 'draft',
})

const loadPosts = async () => {
  loading.value = true
  try {
    const resp = await adminAPI.getBlogList()
    posts.value = resp.data.posts || []
  } catch {
    // API not ready
  } finally {
    loading.value = false
  }
}

const openEditor = (post?: BlogPost) => {
  if (post) {
    Object.assign(editing, post)
  } else {
    Object.assign(editing, {
      id: 0, title: '', slug: '', excerpt: '', content: '',
      author: '', category: '', status: 'draft',
    })
  }
  editorVisible.value = true
}

const handleSave = async () => {
  if (!editing.title || !editing.content) {
    ElMessage.warning('请填写标题和正文')
    return
  }
  saving.value = true
  try {
    if (editing.id) {
      await adminAPI.updateBlogPost(editing.id, { ...editing })
      ElMessage.success('保存成功')
    } else {
      await adminAPI.createBlogPost({ ...editing })
      ElMessage.success('发布成功')
    }
    editorVisible.value = false
    loadPosts()
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

const handleDelete = async (post: BlogPost) => {
  try {
    await ElMessageBox.confirm(`确定删除"${post.title}"？`, '确认', { type: 'warning' })
    await adminAPI.deleteBlogPost(post.id)
    ElMessage.success('已删除')
    loadPosts()
  } catch { /* cancelled */ }
}

onMounted(loadPosts)
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
.content-editor :deep(textarea) {
  font-family: 'Cascadia Code', monospace;
  font-size: 14px;
}
</style>
