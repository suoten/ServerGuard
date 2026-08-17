<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>ServerGuard 博客</h1>
        <p>运维实战、技术分享、产品更新</p>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <div v-if="loading" class="loading-state">
          <el-icon class="rotating"><Loading /></el-icon>
          加载中...
        </div>
        <div v-else-if="posts.length === 0" class="empty-state">
          <p>🚧 博客正在建设中，敬请期待...</p>
          <p class="empty-hint">我们正在准备精彩的运维实战文章</p>
        </div>
        <div v-else>
          <!-- Featured Post -->
          <div class="featured-post card" v-if="posts[0]">
            <div class="featured-tag">置顶</div>
            <router-link :to="`/blog/${posts[0].slug}`">
              <h2>{{ posts[0].title }}</h2>
              <p>{{ posts[0].excerpt }}</p>
              <div class="post-meta">
                <span>{{ posts[0].author }}</span>
                <span>·</span>
                <span>{{ posts[0].category }}</span>
                <span>·</span>
                <span>{{ formatDate(posts[0].created_at) }}</span>
              </div>
            </router-link>
          </div>

          <!-- Post List -->
          <div class="post-grid" v-if="posts.length > 1">
            <div class="post-card card" v-for="post in posts.slice(1)" :key="post.id">
              <router-link :to="`/blog/${post.slug}`">
                <span class="post-category">{{ post.category }}</span>
                <h3>{{ post.title }}</h3>
                <p>{{ post.excerpt }}</p>
                <div class="post-meta">
                  <span>{{ post.author }}</span>
                  <span>·</span>
                  <span>{{ formatDate(post.created_at) }}</span>
                </div>
              </router-link>
            </div>
          </div>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import DefaultLayout from '@/components/DefaultLayout.vue'
import { publicAPI } from '@/composables/useAPI'

interface BlogPost {
  id: number
  title: string
  slug: string
  excerpt: string
  content: string
  author: string
  category: string
  created_at: string
}

const posts = ref<BlogPost[]>([])
const loading = ref(true)

const formatDate = (s: string) => {
  if (!s) return ''
  const d = new Date(s)
  if (isNaN(d.getTime())) return s.slice(0, 10)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

onMounted(async () => {
  try {
    const resp = await publicAPI.getBlogList()
    posts.value = resp.data.posts || []
  } catch {
    // API not ready, show placeholder
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page-hero {
  padding: 60px 0 40px;
  text-align: center;
  background: var(--gradient-hero);
}
.page-hero h1 { font-size: 40px; margin-bottom: 12px; }
.page-hero p { color: var(--text-secondary); }

.loading-state, .empty-state {
  text-align: center;
  padding: 80px 0;
  color: var(--text-secondary);
}
.rotating { animation: spin 1s linear infinite; }
@keyframes spin { 100% { transform: rotate(360deg); } }
.empty-hint { color: var(--text-muted); font-size: 14px; margin-top: 8px; }

.featured-post {
  padding: 40px;
  margin-bottom: 32px;
  position: relative;
}
.featured-tag {
  position: absolute;
  top: 20px; right: 20px;
  background: rgba(253, 203, 110, 0.15);
  color: var(--sg-accent);
  font-size: 12px;
  padding: 4px 12px;
  border-radius: 20px;
}
.featured-post h2 { font-size: 24px; margin-bottom: 12px; }
.featured-post p { color: var(--text-secondary); margin-bottom: 16px; }

.post-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
}
.post-card { padding: 28px; }
.post-card a { display: block; }
.post-category {
  background: rgba(0, 212, 170, 0.1);
  color: var(--sg-primary);
  font-size: 12px;
  padding: 3px 10px;
  border-radius: 12px;
}
.post-card h3 { font-size: 17px; margin: 12px 0 8px; }
.post-card p { color: var(--text-secondary); font-size: 14px; margin-bottom: 12px; }
.post-meta {
  display: flex;
  gap: 6px;
  color: var(--text-muted);
  font-size: 13px;
}

@media (max-width: 768px) {
  .post-grid { grid-template-columns: 1fr; }
}
</style>
