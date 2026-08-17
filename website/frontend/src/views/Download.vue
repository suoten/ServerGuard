<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>下载 ServerGuard</h1>
        <p>16MB 单二进制 · 零依赖 · 支持 Windows 和 Linux</p>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <!-- Quick Install -->
        <div class="install-section card">
          <div class="install-left">
            <h2>⚡ 一键安装（推荐）</h2>
            <p>Linux 用户直接运行以下命令，自动下载安装并注册为系统服务：</p>
            <div class="code-block">
              <span class="prompt">$</span>
              <span class="cmd">curl -sSL https://sg.jjtt.net/install.sh | bash</span>
              <button class="copy-btn" @click="copy('curl -sSL https://sg.jjtt.net/install.sh | bash')">
                <el-icon><CopyDocument /></el-icon>
              </button>
            </div>
            <p class="hint">安装后自动启动，面板地址：http://127.0.0.1:18090</p>
          </div>
          <div class="install-right">
            <div class="terminal-mock">
              <div class="terminal-header">
                <span class="dot red"></span>
                <span class="dot yellow"></span>
                <span class="dot green"></span>
              </div>
              <pre class="terminal-body">ServerGuard Installer
━━━━━━━━━━━━━━━━━━━━━
✓ 检测系统: Linux amd64
✓ 下载 serverguard-agent...
✓ 安装到 /usr/local/bin/
✓ 创建配置 /opt/serverguard/
✓ 注册 systemd 服务...
✓ 启动 serverguard-agent...

完成！你的服务器已开始被守护。</pre>
            </div>
          </div>
        </div>

        <!-- Manual Download -->
        <div class="download-section">
          <h2 class="section-title">手动下载</h2>
          <p class="section-desc">选择适合你系统的版本，下载后可用 SHA256 校验完整性。</p>

          <div v-if="loading" class="loading-state">
            <el-icon class="rotating"><Loading /></el-icon>
            加载版本信息...
          </div>

          <div v-else-if="releases.length === 0" class="empty-state card">
            <p class="empty-title">📦 版本即将发布</p>
            <p class="empty-hint">首个公开版本正在准备中，请稍后再来，或使用上方一键安装命令。</p>
          </div>

          <template v-else>
            <div class="os-tabs">
              <button v-for="tab in osTabs" :key="tab.id"
                :class="{ active: activeOS === tab.id }"
                @click="activeOS = tab.id">
                <span class="os-icon">{{ tab.icon }}</span>
                {{ tab.name }}
              </button>
            </div>

            <div class="download-grid">
              <div class="download-card card" v-for="item in currentDownloads" :key="item.id">
                <div class="dl-header">
                  <span class="dl-icon">{{ platformIcon(item) }}</span>
                  <div>
                    <h3>{{ platformName(item) }}</h3>
                    <p>{{ platformDesc(item) }}</p>
                  </div>
                </div>
                <div class="dl-meta">
                  <span class="dl-version">v{{ item.version }}</span>
                  <span class="dl-size">{{ formatSize(item.file_size) }}</span>
                  <span class="dl-downloads">{{ item.downloads }} 次下载</span>
                </div>
                <div class="dl-actions">
                  <a :href="downloadURL(item)" class="btn btn-primary" :download="fileName(item)">
                    <el-icon><Download /></el-icon>
                    下载
                  </a>
                  <button class="btn btn-outline" @click="copy(item.sha256)">
                    <el-icon><CopyDocument /></el-icon>
                    SHA256
                  </button>
                </div>
                <div class="dl-hash">
                  <span class="hash-label">SHA256:</span>
                  <code :title="item.sha256">{{ item.sha256 }}</code>
                </div>
              </div>
            </div>
          </template>
        </div>

        <!-- Verify Checksum -->
        <div class="verify-section card" v-if="releases.length > 0">
          <h2>🔐 校验文件完整性</h2>
          <p>每个二进制都附带 SHA256 校验值（见下载卡片），下载后校验：</p>
          <div class="code-block multi">
<span class="prompt">$</span> <span class="cmd">sha256sum serverguard-agent</span>
<span class="output"># 输出应与下载卡片上的 SHA256 完全一致</span>
          </div>
          <p class="hint">Windows PowerShell：<code class="pubkey">Get-FileHash .\serverguard-agent.exe -Algorithm SHA256</code></p>
        </div>

        <!-- Release Notes -->
        <div class="history-section" v-if="releases.length > 0">
          <h2 class="section-title">版本历史</h2>
          <div class="release-card card" v-for="rel in releases" :key="rel.version">
            <div class="release-header">
              <div class="release-title">
                <span class="release-version">v{{ rel.version }}</span>
                <span v-if="rel.critical" class="badge badge-new">关键更新</span>
                <span class="release-date">{{ formatDate(rel.created_at) }}</span>
              </div>
              <span class="release-platforms">{{ rel.items.map(platformShort).join(' · ') }}</span>
            </div>
            <div class="release-notes" v-html="renderNotes(rel.release_notes)"></div>
          </div>
        </div>

        <!-- System Requirements -->
        <div class="requirements-section">
          <h2 class="section-title">系统要求</h2>
          <div class="grid-3">
            <div class="req-card card">
              <h3>🐧 Linux</h3>
              <ul>
                <li>Ubuntu 18.04+ / Debian 10+</li>
                <li>CentOS 7+ / Rocky Linux 8+</li>
                <li>Arch Linux / Alpine 3.16+</li>
                <li>内核 3.10+，glibc 2.17+</li>
              </ul>
            </div>
            <div class="req-card card">
              <h3>🪟 Windows</h3>
              <ul>
                <li>Windows Server 2016+</li>
                <li>Windows 10/11 (64位)</li>
                <li>PowerShell 5.1+</li>
                <li>无需额外运行时</li>
              </ul>
            </div>
            <div class="req-card card">
              <h3>💻 资源</h3>
              <ul>
                <li>内存：≥ 256MB（Agent 占用 &lt;50MB）</li>
                <li>CPU：无特殊要求（占用 &lt;1%）</li>
                <li>磁盘：≥ 100MB 可用空间</li>
                <li>端口：18090（本地面板）</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import MarkdownIt from 'markdown-it'
import DefaultLayout from '@/components/DefaultLayout.vue'
import { publicAPI } from '@/composables/useAPI'

const md = new MarkdownIt({ html: false, linkify: true })

interface VersionItem {
  id: number
  version: string
  channel: string
  os: string
  arch: string
  release_notes: string
  sha256: string
  file_size: number
  critical: boolean
  downloads: number
  created_at: string
}

interface ReleaseGroup {
  version: string
  critical: boolean
  release_notes: string
  created_at: string
  items: VersionItem[]
}

const loading = ref(true)
const versions = ref<VersionItem[]>([])
const activeOS = ref('linux')

// 按版本号分组（id 降序即最新在前）
const releases = computed<ReleaseGroup[]>(() => {
  const map = new Map<string, ReleaseGroup>()
  for (const v of versions.value) {
    let g = map.get(v.version)
    if (!g) {
      g = {
        version: v.version,
        critical: v.critical,
        release_notes: v.release_notes,
        created_at: v.created_at,
        items: [],
      }
      map.set(v.version, g)
    }
    if (v.critical) g.critical = true
    g.items.push(v)
  }
  return Array.from(map.values())
})

// 最新版本的平台集合 → OS 选项卡
const latestItems = computed<VersionItem[]>(() => releases.value[0]?.items || [])

// 平台展示顺序：Linux（主平台）优先，其次 Windows、macOS
const osOrder = (os: string) => ({ linux: 0, windows: 1, darwin: 2 } as Record<string, number>)[os] ?? 3

const osTabs = computed(() => {
  const tabs: { id: string; name: string; icon: string }[] = []
  const seen = new Set<string>()
  const sorted = [...latestItems.value].sort((a, b) => osOrder(a.os) - osOrder(b.os))
  for (const item of sorted) {
    if (seen.has(item.os)) continue
    seen.add(item.os)
    if (item.os === 'linux') tabs.push({ id: 'linux', name: 'Linux', icon: '🐧' })
    else if (item.os === 'windows') tabs.push({ id: 'windows', name: 'Windows', icon: '🪟' })
    else if (item.os === 'darwin') tabs.push({ id: 'darwin', name: 'macOS', icon: '🍎' })
    else tabs.push({ id: item.os, name: item.os, icon: '💾' })
  }
  return tabs
})

// 默认选中第一个可用平台（通常是 linux）；当数据尚未加载时回退到 linux
watch(osTabs, (tabs) => {
  if (tabs.length > 0 && !tabs.some((t) => t.id === activeOS.value)) {
    activeOS.value = tabs[0].id
  }
})

const currentDownloads = computed(() =>
  latestItems.value
    .filter((i) => i.os === activeOS.value)
    .sort((a, b) => a.arch.localeCompare(b.arch))
)

const platformIcon = (item: VersionItem) => {
  if (item.os === 'linux') return item.arch === 'arm64' ? '🍓' : '🐧'
  if (item.os === 'windows') return '🪟'
  if (item.os === 'darwin') return '🍎'
  return '💾'
}

const platformName = (item: VersionItem) => {
  const osName: Record<string, string> = { linux: 'Linux', windows: 'Windows', darwin: 'macOS' }
  const archName: Record<string, string> = { amd64: 'amd64 (64位)', arm64: 'arm64 (ARM)' }
  return `${osName[item.os] || item.os} ${archName[item.arch] || item.arch}`
}

const platformDesc = (item: VersionItem) => {
  if (item.os === 'linux' && item.arch === 'amd64') return '适用于大多数 x86 服务器（CentOS/Ubuntu/Debian）'
  if (item.os === 'linux' && item.arch === 'arm64') return '适用于 ARM 服务器 / 树莓派 / 国产 ARM 机型'
  if (item.os === 'windows') return '适用于 Windows Server 2016+ / Win10/11'
  if (item.os === 'darwin') return '适用于 macOS'
  return ''
}

const platformShort = (item: VersionItem) => `${item.os}/${item.arch}`

const downloadURL = (item: VersionItem) => `/api/v1/download/${item.id}`

const fileName = (item: VersionItem) =>
  `serverguard-agent-${item.os}-${item.arch}${item.os === 'windows' ? '.exe' : ''}`

const formatSize = (bytes: number) => {
  if (!bytes) return ''
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${Math.round(bytes / 1024)} KB`
}

const formatDate = (s: string) => (s || '').slice(0, 10)

const renderNotes = (notes: string) => md.render(notes || '')

const copy = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('请手动复制')
  }
}

onMounted(async () => {
  try {
    const resp = await publicAPI.getVersions()
    versions.value = resp.data.versions || []
    if (osTabs.value.length > 0) {
      activeOS.value = osTabs.value[0].id
    }
  } catch {
    // 版本接口不可用 → 显示空状态
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

/* Install */
.install-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 40px;
  padding: 40px;
  margin-bottom: 64px;
}
.install-left h2 { font-size: 22px; margin-bottom: 12px; }
.install-left p { color: var(--text-secondary); margin-bottom: 16px; }
.code-block {
  display: flex;
  align-items: center;
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 14px 18px;
  gap: 8px;
}
.prompt { color: var(--text-muted); font-family: monospace; }
.cmd { color: var(--sg-primary); font-family: monospace; font-size: 14px; flex: 1; }
.copy-btn {
  background: rgba(0, 212, 170, 0.1);
  border: none;
  color: var(--sg-primary);
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 4px;
}
.hint { color: var(--text-muted); font-size: 13px; margin-top: 12px; }

.terminal-mock {
  background: #0d1117;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.terminal-header {
  background: #161b22;
  padding: 10px 14px;
  display: flex;
  gap: 8px;
}
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot.red { background: #e74c3c; }
.dot.yellow { background: #f1c40f; }
.dot.green { background: #27ae60; }
.terminal-body {
  padding: 16px;
  font-family: monospace;
  font-size: 13px;
  color: var(--sg-primary);
  white-space: pre;
  line-height: 1.6;
}

/* Download */
.section-title { font-size: 24px; margin-bottom: 8px; }
.section-desc { color: var(--text-secondary); margin-bottom: 24px; }

.loading-state {
  text-align: center;
  padding: 48px 0;
  color: var(--text-secondary);
}
.rotating { animation: spin 1s linear infinite; }
@keyframes spin { 100% { transform: rotate(360deg); } }

.empty-state { text-align: center; padding: 48px; margin-bottom: 64px; }
.empty-title { font-size: 18px; margin-bottom: 8px; }
.empty-hint { color: var(--text-muted); font-size: 14px; }

.os-tabs {
  display: flex;
  gap: 12px;
  margin-bottom: 32px;
  flex-wrap: wrap;
}
.os-tabs button {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 10px 20px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}
.os-tabs button.active {
  border-color: var(--sg-primary);
  color: var(--sg-primary);
  background: rgba(0, 212, 170, 0.08);
}

.download-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
  margin-bottom: 64px;
}
.download-card { padding: 28px; }
.dl-header { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
.dl-icon { font-size: 32px; }
.dl-header h3 { font-size: 17px; }
.dl-header p { color: var(--text-muted); font-size: 13px; }
.dl-meta { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; }
.dl-version { background: rgba(0, 212, 170, 0.1); color: var(--sg-primary); padding: 4px 12px; border-radius: 20px; font-size: 13px; }
.dl-size { color: var(--text-muted); font-size: 13px; }
.dl-downloads { color: var(--text-muted); font-size: 12px; }
.dl-actions { display: flex; gap: 12px; margin-bottom: 16px; }
.dl-actions .btn { text-decoration: none; }
.dl-hash { display: flex; align-items: center; gap: 8px; }
.hash-label { color: var(--text-muted); font-size: 12px; white-space: nowrap; }
.dl-hash code {
  color: var(--text-secondary);
  font-family: monospace;
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Verify */
.verify-section { padding: 40px; margin-bottom: 64px; }
.verify-section h2 { font-size: 22px; margin-bottom: 12px; }
.verify-section p { color: var(--text-secondary); margin-bottom: 16px; }
.verify-section .code-block {
  display: block;
  padding: 16px 20px;
  font-family: monospace;
}
.code-block.multi { line-height: 1.8; }
.code-block.multi > span { display: block; }
.code-block.multi > span.prompt,
.code-block.multi > span.cmd { display: inline; }
.output { color: var(--text-muted); }
.pubkey {
  color: var(--text-secondary);
  font-family: monospace;
  font-size: 12px;
  word-break: break-all;
}

/* History */
.history-section { margin-bottom: 64px; }
.release-card { padding: 28px; margin-bottom: 16px; }
.release-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}
.release-title { display: flex; align-items: center; gap: 12px; }
.release-version { font-size: 18px; font-weight: 700; color: var(--text-primary); }
.release-date { color: var(--text-muted); font-size: 13px; }
.release-platforms { color: var(--text-muted); font-size: 13px; font-family: monospace; }
.release-notes { color: var(--text-secondary); font-size: 14px; line-height: 1.7; }
.release-notes :deep(h1),
.release-notes :deep(h2),
.release-notes :deep(h3) {
  font-size: 15px;
  margin: 12px 0 8px;
  color: var(--text-primary);
}
.release-notes :deep(ul) { padding-left: 20px; }
.release-notes :deep(code) {
  background: rgba(0, 0, 0, 0.3);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 12px;
}

/* Requirements */
.req-card { padding: 28px; }
.req-card h3 { font-size: 18px; margin-bottom: 12px; }
.req-card ul { list-style: none; }
.req-card li {
  color: var(--text-secondary);
  font-size: 14px;
  padding: 4px 0;
}
.req-card li::before { content: '•'; color: var(--sg-primary); margin-right: 8px; }

@media (max-width: 768px) {
  .install-section { grid-template-columns: 1fr; padding: 24px; }
  .download-grid { grid-template-columns: 1fr; }
  .verify-section { padding: 24px; }
}
</style>
