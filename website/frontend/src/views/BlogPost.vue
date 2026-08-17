<template>
  <DefaultLayout>
    <section class="section">
      <div class="container narrow">
        <div v-if="loading" class="loading-state">
          <el-icon class="rotating"><Loading /></el-icon>
          加载中...
        </div>
        <template v-else-if="post">
          <router-link to="/blog" class="back-link">← 返回博客</router-link>
          <span class="post-category">{{ post.category }}</span>
          <h1 class="post-title">{{ post.title }}</h1>
          <div class="post-meta">
            <span>{{ post.author }}</span>
            <span>·</span>
            <span>{{ formatDate(post.created_at) }}</span>
            <span>·</span>
            <span>{{ post.views }} 次阅读</span>
          </div>
          <div class="post-content" v-html="renderedContent"></div>
        </template>
        <div v-else class="empty-state">
          <p>文章不存在</p>
          <router-link to="/blog" class="btn btn-outline">返回博客</router-link>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import MarkdownIt from 'markdown-it'
import hljs from 'highlight.js'
import DefaultLayout from '@/components/DefaultLayout.vue'
import { publicAPI } from '@/composables/useAPI'

const route = useRoute()
const md = new MarkdownIt({
  html: true,
  linkify: true,
  highlight(str: string, lang: string) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return `<pre class="hljs"><code>${hljs.highlight(str, { language: lang }).value}</code></pre>`
      } catch { /* */ }
    }
    return `<pre class="hljs"><code>${md.utils.escapeHtml(str)}</code></pre>`
  },
})

const post = ref<{
  id: number; title: string; content: string; author: string;
  category: string; created_at: string; views: number
} | null>(null)
const loading = ref(true)

const renderedContent = computed(() => {
  if (!post.value) return ''
  return md.render(post.value.content)
})

const loadPost = async () => {
  loading.value = true
  try {
    const slug = route.params.slug as string
    const resp = await publicAPI.getBlogPost(slug)
    post.value = resp.data
    document.title = `${post.value.title} · ServerGuard`
  } catch {
    post.value = null
    document.title = '文章不存在 · ServerGuard'
  } finally {
    loading.value = false
  }
}

const formatDate = (s: string) => {
  if (!s) return ''
  const d = new Date(s)
  if (isNaN(d.getTime())) return s.slice(0, 10)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

onMounted(loadPost)
watch(() => route.params.slug, loadPost)
</script>

<style scoped>
.narrow { max-width: 760px; }
.loading-state, .empty-state {
  text-align: center;
  padding: 80px 0;
}
.rotating { animation: spin 1s linear infinite; }
@keyframes spin { 100% { transform: rotate(360deg); } }
.back-link {
  display: inline-block;
  color: var(--text-secondary);
  font-size: 14px;
  margin-bottom: 24px;
}
.post-category {
  background: rgba(0, 212, 170, 0.1);
  color: var(--sg-primary);
  font-size: 13px;
  padding: 4px 12px;
  border-radius: 12px;
}
.post-title {
  font-size: 32px;
  margin: 16px 0 12px;
}
.post-meta {
  display: flex;
  gap: 6px;
  color: var(--text-muted);
  font-size: 14px;
  margin-bottom: 40px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--border-color);
}
.post-content {
  color: var(--text-primary);
  font-size: 16px;
  line-height: 1.8;
}
.post-content :deep(h2) {
  font-size: 24px;
  margin: 32px 0 16px;
}
.post-content :deep(h3) {
  font-size: 20px;
  margin: 24px 0 12px;
}
.post-content :deep(p) {
  margin-bottom: 16px;
}
.post-content :deep(ul), .post-content :deep(ol) {
  margin: 0 0 16px 24px;
}
.post-content :deep(li) {
  margin-bottom: 8px;
}
.post-content :deep(pre) {
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 16px 20px;
  overflow-x: auto;
  margin-bottom: 16px;
}
.post-content :deep(code) {
  font-family: 'Cascadia Code', monospace;
  font-size: 14px;
}
.post-content :deep(blockquote) {
  border-left: 3px solid var(--sg-primary);
  padding-left: 16px;
  color: var(--text-secondary);
  margin-bottom: 16px;
}
</style>
