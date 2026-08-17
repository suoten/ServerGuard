<template>
  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid">
        <div class="footer-brand">
          <div class="logo">
            <svg class="logo-icon" viewBox="0 0 32 32" fill="none">
              <path d="M16 2L4 7v9c0 7 5.2 12.8 12 14 6.8-1.2 12-7 12-14V7L16 2z"
                stroke="#00d4aa" stroke-width="2" fill="rgba(0,212,170,0.08)"/>
              <path d="M11 16l3.5 3.5L21 13" stroke="#00d4aa" stroke-width="2.5"
                stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>ServerGuard</span>
          </div>
          <p class="footer-desc">让服务器自己照顾自己。7×24 小时自动守护、自动修复、自动告警。</p>
          <p class="footer-slogan"><em>Install &amp; Forget. Guard &amp; Heal.</em></p>
        </div>

        <div class="footer-col">
          <h4>产品</h4>
          <router-link to="/download">下载</router-link>
          <router-link to="/pricing">定价</router-link>
          <router-link to="/docs">文档</router-link>
          <router-link to="/blog">博客</router-link>
        </div>

        <div class="footer-col">
          <h4>资源</h4>
          <router-link to="/security">安全公告</router-link>
          <a href="https://github.com/suoten/serverguard" target="_blank">GitHub</a>
          <router-link to="/docs">快速开始</router-link>
          <router-link to="/docs">故障排查</router-link>
        </div>

        <div class="footer-col">
          <h4>公司</h4>
          <router-link to="/about">关于我们</router-link>
          <a href="mailto:security@serverguard.cn">安全披露</a>
        </div>
      </div>

      <div class="footer-bottom">
        <p>&copy; {{ year }} ServerGuard. All rights reserved.</p>
        <p>用 ❤️ 在中国制造</p>
      </div>
    </div>
  </footer>
</template>

<script setup lang="ts">
const year = new Date().getFullYear()
</script>

<style scoped>
.site-footer {
  background: var(--bg-footer);
  border-top: 1px solid var(--border-color);
  padding: 48px 0 24px;
}
.footer-grid {
  display: grid;
  grid-template-columns: 2fr 1fr 1fr 1fr;
  gap: 40px;
  margin-bottom: 32px;
}
.footer-brand .logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 18px;
  margin-bottom: 12px;
}
.logo-icon { width: 28px; height: 28px; }
.footer-desc {
  color: var(--text-secondary);
  font-size: 14px;
  margin-bottom: 8px;
  max-width: 320px;
}
.footer-slogan {
  color: var(--text-muted);
  font-size: 13px;
}
.footer-col h4 {
  font-size: 15px;
  margin-bottom: 16px;
  color: var(--text-primary);
}
.footer-col a {
  display: block;
  color: var(--text-secondary);
  font-size: 14px;
  margin-bottom: 10px;
  transition: color 0.2s;
}
.footer-col a:hover { color: var(--sg-primary); }
.footer-bottom {
  border-top: 1px solid var(--border-color);
  padding-top: 20px;
  display: flex;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 13px;
}

@media (max-width: 768px) {
  .footer-grid { grid-template-columns: 1fr 1fr; gap: 24px; }
  .footer-bottom { flex-direction: column; gap: 8px; text-align: center; }
}
</style>
