<template>
  <div class="dashboard">
    <div class="stat-grid">
      <div class="stat-card card">
        <div class="stat-icon">📦</div>
        <div class="stat-data">
          <div class="stat-num">{{ stats.versions }}</div>
          <div class="stat-label">已发布版本</div>
        </div>
      </div>
      <div class="stat-card card">
        <div class="stat-icon">📥</div>
        <div class="stat-data">
          <div class="stat-num">{{ stats.downloads }}</div>
          <div class="stat-label">总下载量</div>
        </div>
      </div>
      <div class="stat-card card">
        <div class="stat-icon">📝</div>
        <div class="stat-data">
          <div class="stat-num">{{ stats.blogPosts }}</div>
          <div class="stat-label">博客文章</div>
        </div>
      </div>
      <div class="stat-card card">
        <div class="stat-icon">🔒</div>
        <div class="stat-data">
          <div class="stat-num">{{ stats.securityAdvisories }}</div>
          <div class="stat-label">安全公告</div>
        </div>
      </div>
    </div>

    <div class="quick-actions card">
      <h3>快捷操作</h3>
      <div class="action-grid">
        <router-link to="/admin/versions" class="action-btn">
          <el-icon><Upload /></el-icon>
          上传新版本
        </router-link>
        <router-link to="/admin/blog" class="action-btn">
          <el-icon><EditPen /></el-icon>
          写博客
        </router-link>
        <router-link to="/admin/content" class="action-btn">
          <el-icon><Document /></el-icon>
          编辑网站内容
        </router-link>
        <router-link to="/admin/pricing" class="action-btn">
          <el-icon><PriceTag /></el-icon>
          修改定价
        </router-link>
      </div>
    </div>

    <div class="info-section">
      <div class="info-card card">
        <h3>💡 版本更新机制说明</h3>
        <p>上传新版本后，Agent 端会通过 <code>/api/v1/latest</code> 接口检测更新：</p>
        <ol>
          <li>在"版本管理"页面上传新的二进制文件</li>
          <li>填写版本号（如 0.1.1）、SHA256、更新日志</li>
          <li>发布后，Agent 启动时自动检测到新版本</li>
          <li>Agent 面板提示用户"有新版本可用"</li>
          <li>用户确认升级 → Agent 下载 → SHA256 校验 → 原子替换 → 重启</li>
        </ol>
      </div>
      <div class="info-card card">
        <h3>💰 免费转收费策略</h3>
        <p>当前所有版本可标记为"免费"或"即将上线"：</p>
        <ul>
          <li>在"定价管理"页面可随时修改价格和可用状态</li>
          <li>前期：社区版免费，专业版标记"限时免费"或"即将上线"</li>
          <li>有用户基础后：在定价管理页面修改价格即可开始收费</li>
          <li>定价修改实时生效，无需重新部署</li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { adminAPI } from '@/composables/useAPI'

const stats = ref({
  versions: 0,
  downloads: 0,
  blogPosts: 0,
  securityAdvisories: 0,
})

onMounted(async () => {
  try {
    const resp = await adminAPI.getDashboardStats()
    stats.value = resp.data
  } catch {
    // Use defaults
  }
})
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  margin-bottom: 24px;
}
.stat-card {
  padding: 24px;
  display: flex;
  align-items: center;
  gap: 16px;
}
.stat-icon { font-size: 36px; }
.stat-num { font-size: 28px; font-weight: 700; }
.stat-label { color: var(--text-secondary); font-size: 14px; }

.quick-actions { padding: 28px; margin-bottom: 24px; }
.quick-actions h3 { font-size: 18px; margin-bottom: 20px; }
.action-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}
.action-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 24px;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  font-size: 14px;
  transition: all 0.2s;
}
.action-btn:hover {
  border-color: var(--sg-primary);
  color: var(--sg-primary);
  background: rgba(0, 212, 170, 0.05);
}
.action-btn .el-icon { font-size: 28px; }

.info-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}
.info-card { padding: 28px; }
.info-card h3 { font-size: 17px; margin-bottom: 12px; }
.info-card p { color: var(--text-secondary); font-size: 14px; margin-bottom: 12px; }
.info-card ol, .info-card ul { margin: 0 0 12px 20px; }
.info-card li { color: var(--text-secondary); font-size: 14px; margin-bottom: 6px; }
.info-card code {
  background: rgba(0, 0, 0, 0.3);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 13px;
  color: var(--sg-primary);
}

@media (max-width: 768px) {
  .stat-grid { grid-template-columns: 1fr 1fr; }
  .action-grid { grid-template-columns: 1fr 1fr; }
  .info-section { grid-template-columns: 1fr; }
}
</style>
