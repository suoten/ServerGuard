<template>
  <header class="site-header" :class="{ scrolled: isScrolled }">
    <div class="container header-inner">
      <router-link to="/" class="logo">
        <svg class="logo-icon" viewBox="0 0 32 32" fill="none">
          <path d="M16 2L4 7v9c0 7 5.2 12.8 12 14 6.8-1.2 12-7 12-14V7L16 2z"
            stroke="url(#lg)" stroke-width="2" fill="rgba(0,212,170,0.08)"/>
          <path d="M11 16l3.5 3.5L21 13" stroke="url(#lg)" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
          <defs>
            <linearGradient id="lg" x1="0" y1="0" x2="32" y2="32">
              <stop stop-color="#00d4aa"/><stop offset="1" stop-color="#00b894"/>
            </linearGradient>
          </defs>
        </svg>
        <span class="logo-text">ServerGuard</span>
      </router-link>

      <nav class="nav-links" :class="{ open: menuOpen }">
        <router-link to="/" @click="menuOpen = false">首页</router-link>
        <router-link to="/pricing" @click="menuOpen = false">定价</router-link>
        <router-link to="/download" @click="menuOpen = false">下载</router-link>
        <router-link to="/docs" @click="menuOpen = false">文档</router-link>
        <router-link to="/blog" @click="menuOpen = false">博客</router-link>
        <router-link to="/security" @click="menuOpen = false">安全公告</router-link>
        <router-link to="/about" @click="menuOpen = false">关于</router-link>
      </nav>

      <div class="header-actions">
        <router-link to="/download" class="btn btn-primary btn-sm">
          <el-icon><Download /></el-icon>
          免费下载
        </router-link>
        <button class="menu-toggle" @click="menuOpen = !menuOpen">
          <el-icon><Menu v-if="!menuOpen" /><Close v-else /></el-icon>
        </button>
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

const isScrolled = ref(false)
const menuOpen = ref(false)

const onScroll = () => {
  isScrolled.value = window.scrollY > 20
}

onMounted(() => window.addEventListener('scroll', onScroll))
onUnmounted(() => window.removeEventListener('scroll', onScroll))
</script>

<style scoped>
.site-header {
  position: fixed;
  top: 0; left: 0; right: 0;
  height: var(--header-height);
  background: var(--bg-header);
  backdrop-filter: blur(20px);
  border-bottom: 1px solid transparent;
  z-index: 1000;
  transition: border-color 0.3s, box-shadow 0.3s;
}
.site-header.scrolled {
  border-bottom-color: var(--border-color);
  box-shadow: var(--shadow-sm);
}
.header-inner {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 700;
  font-size: 18px;
  color: var(--text-primary);
}
.logo-icon { width: 28px; height: 28px; }
.nav-links {
  display: flex;
  align-items: center;
  gap: 28px;
}
.nav-links a {
  color: var(--text-secondary);
  font-size: 15px;
  font-weight: 500;
  transition: color 0.2s;
}
.nav-links a:hover, .nav-links a.router-link-active {
  color: var(--sg-primary);
}
.header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.btn-sm { padding: 8px 18px; font-size: 14px; }
.menu-toggle {
  display: none;
  background: none;
  border: none;
  color: var(--text-primary);
  font-size: 22px;
  cursor: pointer;
}

@media (max-width: 768px) {
  .nav-links {
    position: fixed;
    top: var(--header-height);
    left: 0; right: 0;
    background: var(--bg-card);
    flex-direction: column;
    padding: 24px;
    gap: 16px;
    border-bottom: 1px solid var(--border-color);
    transform: translateY(-200%);
    transition: transform 0.3s;
  }
  .nav-links.open { transform: translateY(0); }
  .menu-toggle { display: block; }
}
</style>
