<template>
  <div class="content-editor">
    <div class="page-card card">
      <div class="card-header">
        <h3>网站内容编辑</h3>
        <el-button type="primary" :loading="saving" @click="handleSave">保存修改</el-button>
      </div>
      <el-tabs v-model="activeTab" class="content-tabs">
        <el-tab-pane label="首页 Hero" name="hero">
          <el-form label-position="top" class="edit-form">
            <el-form-item label="Badge 文字">
              <el-input v-model="content.hero_badge" placeholder="v0.1.0 社区版现已发布 · 完全免费" />
            </el-form-item>
            <el-form-item label="主标题（第一行）">
              <el-input v-model="content.hero_title_line1" placeholder="你的服务器" />
            </el-form-item>
            <el-form-item label="主标题（第二行，渐变色）">
              <el-input v-model="content.hero_title_line2" placeholder="7×24 小时自动守护" />
            </el-form-item>
            <el-form-item label="副标题">
              <el-input
                v-model="content.hero_subtitle"
                type="textarea"
                :rows="3"
                placeholder="资源监控 → 异常检测 → 自动修复 → 微信告警..."
              />
            </el-form-item>
            <el-form-item label="安装命令">
              <el-input v-model="content.install_command" placeholder="curl -sSL https://... | bash" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="首页功能" name="features">
          <div class="features-editor">
            <div v-for="(f, i) in content.features" :key="i" class="feature-edit-row">
              <el-input v-model="f.icon" placeholder="🔥" style="width: 60px" />
              <el-input v-model="f.title" placeholder="功能名称" />
              <el-input v-model="f.desc" placeholder="功能描述" />
              <el-button type="danger" @click="content.features.splice(i, 1)" :icon="Delete" circle />
            </div>
            <el-button @click="content.features.push({ icon: '', title: '', desc: '' })">
              + 添加功能
            </el-button>
          </div>
        </el-tab-pane>

        <el-tab-pane label="统计数字" name="stats">
          <div class="stats-editor">
            <div v-for="(s, i) in content.stats" :key="i" class="stat-edit-row">
              <el-input v-model="s.value" placeholder="16MB" style="width: 120px" />
              <el-input v-model="s.label" placeholder="单二进制大小" />
              <el-button type="danger" @click="content.stats.splice(i, 1)" :icon="Delete" circle />
            </div>
            <el-button @click="content.stats.push({ value: '', label: '' })">
              + 添加统计
            </el-button>
          </div>
        </el-tab-pane>

        <el-tab-pane label="FAQ" name="faq">
          <div class="faq-editor">
            <div v-for="(f, i) in content.faqs" :key="i" class="faq-edit-row card">
              <el-input v-model="f.q" placeholder="问题" />
              <el-input v-model="f.a" type="textarea" :rows="2" placeholder="回答" />
              <el-button type="danger" @click="content.faqs.splice(i, 1)" :icon="Delete" circle>
                删除
              </el-button>
            </div>
            <el-button @click="content.faqs.push({ q: '', a: '' })">
              + 添加 FAQ
            </el-button>
          </div>
        </el-tab-pane>

        <el-tab-pane label="证言" name="testimonial">
          <el-form label-position="top" class="edit-form">
            <el-form-item label="证言内容">
              <el-input v-model="content.testimonial_quote" type="textarea" :rows="4" />
            </el-form-item>
            <el-form-item label="作者名">
              <el-input v-model="content.testimonial_author" placeholder="某独立开发者" />
            </el-form-item>
            <el-form-item label="作者角色">
              <el-input v-model="content.testimonial_role" placeholder="5 台服务器的全栈开发者" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="页脚" name="footer">
          <el-form label-position="top" class="edit-form">
            <el-form-item label="页脚描述">
              <el-input v-model="content.footer_desc" type="textarea" :rows="2" />
            </el-form-item>
            <el-form-item label="Slogan">
              <el-input v-model="content.footer_slogan" />
            </el-form-item>
            <el-form-item label="GitHub 链接">
              <el-input v-model="content.github_url" />
            </el-form-item>
            <el-form-item label="联系邮箱">
              <el-input v-model="content.contact_email" />
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Delete } from '@element-plus/icons-vue'
import { adminAPI } from '@/composables/useAPI'

const activeTab = ref('hero')
const saving = ref(false)

const content = reactive({
  hero_badge: '',
  hero_title_line1: '',
  hero_title_line2: '',
  hero_subtitle: '',
  install_command: '',
  features: [] as { icon: string; title: string; desc: string }[],
  stats: [] as { value: string; label: string }[],
  faqs: [] as { q: string; a: string }[],
  testimonial_quote: '',
  testimonial_author: '',
  testimonial_role: '',
  footer_desc: '',
  footer_slogan: '',
  github_url: '',
  contact_email: '',
})

onMounted(async () => {
  try {
    const resp = await adminAPI.getContent()
    Object.assign(content, resp.data)
  } catch {
    // Use defaults
  }
})

const handleSave = async () => {
  saving.value = true
  try {
    await adminAPI.updateContent(content)
    ElMessage.success('保存成功')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}
</script>

<style scoped>
.page-card { padding: 28px; }
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}
.card-header h3 { font-size: 18px; }
.edit-form { max-width: 600px; }
.feature-edit-row, .stat-edit-row, .faq-edit-row {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
  align-items: center;
}
.faq-edit-row {
  flex-direction: column;
  align-items: stretch;
  padding: 16px;
}
</style>
