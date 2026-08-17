<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>安全公告</h1>
        <p>CVE 漏洞披露、影响版本、修复版本、升级指南</p>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <div v-if="loading" class="loading-state">
          <el-icon class="rotating"><Loading /></el-icon>
          加载中...
        </div>
        <div v-else-if="advisories.length === 0" class="empty-state">
          <h2>🎉 暂无安全漏洞</h2>
          <p>ServerGuard 尚无已知安全漏洞。</p>
          <p class="empty-hint">如发现安全漏洞，请通过 security@serverguard.cn 私下报告。</p>
        </div>
        <div v-else class="advisory-list">
          <div class="advisory-card card" v-for="adv in advisories" :key="adv.id">
            <div class="advisory-header">
              <span class="severity-badge" :class="`sev-${adv.severity}`">
                {{ severityLabel(adv.severity) }}
              </span>
              <span class="cve-id">{{ adv.cve_id }}</span>
              <span v-if="adv.patched_version" class="patched">
                修复版本: v{{ adv.patched_version }}
              </span>
            </div>
            <h3>{{ adv.title }}</h3>
            <p class="advisory-summary">{{ adv.summary }}</p>
            <div class="advisory-meta">
              <span>📅 {{ adv.published_at }}</span>
              <span v-if="adv.affected_versions">影响版本: {{ adv.affected_versions }}</span>
            </div>
            <details class="advisory-details">
              <summary>查看详情</summary>
              <div class="advisory-detail-content" v-html="renderMarkdown(adv.description)"></div>
            </details>
          </div>
        </div>

        <!-- Security Policy -->
        <div class="security-policy card">
          <h2>🔐 安全披露政策</h2>
          <p>我们非常重视 ServerGuard 的安全性。如果你发现了安全漏洞，请按以下流程报告：</p>
          <ol>
            <li>不要公开披露，先通过 <a href="mailto:security@serverguard.cn">security@serverguard.cn</a> 私下报告</li>
            <li>附上漏洞的详细描述、复现步骤、影响范围</li>
            <li>我们将在 48 小时内回复确认收到</li>
            <li>修复后在安全公告页发布，并致谢报告者</li>
            <li>严重漏洞报告者可获得专业版 1 年免费授权</li>
          </ol>
          <p class="policy-note">
            PGP 公钥：
            <code class="pubkey">-----BEGIN PGP PUBLIC KEY BLOCK-----</code>
          </p>
          <p>所有 Release 二进制使用 Ed25519 签名，签名公钥在官网公开。</p>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import MarkdownIt from 'markdown-it'
import DefaultLayout from '@/components/DefaultLayout.vue'
import { publicAPI } from '@/composables/useAPI'

const md = new MarkdownIt({ html: true, linkify: true })

interface Advisory {
  id: number; cve_id: string; title: string; summary: string;
  description: string; severity: string; affected_versions: string;
  patched_version: string; published_at: string
}

const advisories = ref<Advisory[]>([])
const loading = ref(true)

const renderMarkdown = (content: string) => md.render(content || '')

const severityLabel = (sev: string) => {
  const map: Record<string, string> = {
    critical: '🔴 严重',
    high: '🟠 高危',
    medium: '🟡 中危',
    low: '🟢 低危',
  }
  return map[sev] || sev
}

onMounted(async () => {
  try {
    const resp = await publicAPI.getSecurityList()
    advisories.value = resp.data.advisories || []
  } catch {
    // API not ready
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
  padding: 60px 0;
  color: var(--text-secondary);
}
.rotating { animation: spin 1s linear infinite; }
@keyframes spin { 100% { transform: rotate(360deg); } }
.empty-hint { color: var(--text-muted); font-size: 14px; margin-top: 8px; }

.advisory-list { margin-bottom: 48px; }
.advisory-card { padding: 28px; margin-bottom: 16px; }
.advisory-header { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.severity-badge {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
}
.sev-critical { background: rgba(231, 76, 60, 0.2); color: #e74c3c; }
.sev-high { background: rgba(243, 156, 18, 0.2); color: #f39c12; }
.sev-medium { background: rgba(241, 196, 15, 0.2); color: #f1c40f; }
.sev-low { background: rgba(39, 174, 96, 0.2); color: #27ae60; }
.cve-id { color: var(--text-secondary); font-family: monospace; font-size: 14px; }
.patched { color: var(--sg-primary); font-size: 13px; }
.advisory-card h3 { font-size: 18px; margin-bottom: 8px; }
.advisory-summary { color: var(--text-secondary); font-size: 14px; margin-bottom: 12px; }
.advisory-meta { display: flex; gap: 16px; color: var(--text-muted); font-size: 13px; }
.advisory-details { margin-top: 12px; }
.advisory-details summary {
  cursor: pointer;
  color: var(--sg-primary);
  font-size: 14px;
}
.advisory-detail-content {
  margin-top: 12px;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.7;
}
.advisory-detail-content :deep(code) {
  background: rgba(0, 0, 0, 0.3);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
}

.security-policy { padding: 40px; }
.security-policy h2 { font-size: 22px; margin-bottom: 16px; }
.security-policy p { color: var(--text-secondary); margin-bottom: 12px; }
.security-policy ol { margin: 0 0 16px 24px; }
.security-policy li { color: var(--text-secondary); margin-bottom: 8px; }
.policy-note { font-size: 13px; }
.pubkey { font-family: monospace; font-size: 12px; color: var(--text-muted); }
</style>
