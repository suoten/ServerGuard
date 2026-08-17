<template>
  <div class="admin-layout">
    <aside class="admin-sidebar" :class="{ collapsed: isCollapsed }">
      <div class="sidebar-header">
        <svg class="sidebar-logo" viewBox="0 0 32 32" fill="none">
          <path d="M16 2L4 7v9c0 7 5.2 12.8 12 14 6.8-1.2 12-7 12-14V7L16 2z"
            stroke="#00d4aa" stroke-width="2" fill="rgba(0,212,170,0.08)"/>
          <path d="M11 16l3.5 3.5L21 13" stroke="#00d4aa" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span v-if="!isCollapsed" class="sidebar-title">管理后台</span>
      </div>
      <nav class="sidebar-nav">
        <router-link to="/admin" class="nav-item" :class="{ active: $route.name === 'AdminDashboard' }">
          <el-icon><DataAnalysis /></el-icon>
          <span v-if="!isCollapsed">仪表盘</span>
        </router-link>
        <router-link to="/admin/content" class="nav-item" :class="{ active: $route.name === 'AdminContent' }">
          <el-icon><Document /></el-icon>
          <span v-if="!isCollapsed">网站内容</span>
        </router-link>
        <router-link to="/admin/pricing" class="nav-item" :class="{ active: $route.name === 'AdminPricing' }">
          <el-icon><PriceTag /></el-icon>
          <span v-if="!isCollapsed">定价管理</span>
        </router-link>
        <router-link to="/admin/versions" class="nav-item" :class="{ active: $route.name === 'AdminVersions' }">
          <el-icon><Upload /></el-icon>
          <span v-if="!isCollapsed">版本管理</span>
        </router-link>
        <router-link to="/admin/blog" class="nav-item" :class="{ active: $route.name === 'AdminBlog' }">
          <el-icon><EditPen /></el-icon>
          <span v-if="!isCollapsed">博客管理</span>
        </router-link>
        <router-link to="/admin/security" class="nav-item" :class="{ active: $route.name === 'AdminSecurity' }">
          <el-icon><Warning /></el-icon>
          <span v-if="!isCollapsed">安全公告</span>
        </router-link>
      </nav>
      <div class="sidebar-footer">
        <button class="nav-item" @click="showPasswordDialog = true">
          <el-icon><Lock /></el-icon>
          <span v-if="!isCollapsed">修改密码</span>
        </button>
        <a href="/" class="nav-item" target="_blank">
          <el-icon><Link /></el-icon>
          <span v-if="!isCollapsed">查看官网</span>
        </a>
        <button class="nav-item logout" @click="handleLogout">
          <el-icon><SwitchButton /></el-icon>
          <span v-if="!isCollapsed">退出登录</span>
        </button>
      </div>
    </aside>

    <div class="admin-main">
      <header class="admin-topbar">
        <button class="collapse-btn" @click="isCollapsed = !isCollapsed">
          <el-icon><Fold v-if="!isCollapsed" /><Expand v-else /></el-icon>
        </button>
        <h2 class="page-title">{{ currentTitle }}</h2>
      </header>
      <div class="admin-content">
        <router-view />
      </div>
    </div>

    <!-- 修改密码弹窗 -->
    <el-dialog v-model="showPasswordDialog" title="修改密码" width="420px">
      <el-form label-width="80px" :model="pwForm">
        <el-form-item label="旧密码">
          <el-input v-model="pwForm.oldPassword" type="password" show-password placeholder="请输入当前密码" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwForm.newPassword" type="password" show-password placeholder="至少 6 位" />
        </el-form-item>
        <el-form-item label="确认密码">
          <el-input v-model="pwForm.confirmPassword" type="password" show-password placeholder="再次输入新密码" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showPasswordDialog = false">取消</el-button>
        <el-button type="primary" :loading="pwLoading" @click="handleChangePassword">确认修改</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { adminAPI } from '@/composables/useAPI'

const route = useRoute()
const router = useRouter()
const isCollapsed = ref(false)

const currentTitle = computed(() => (route.meta.title as string || '').replace(' · 管理后台', ''))

const handleLogout = () => {
  localStorage.removeItem('sg_admin_token')
  router.push('/admin/login')
}

// 修改密码
const showPasswordDialog = ref(false)
const pwLoading = ref(false)
const pwForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' })

const handleChangePassword = async () => {
  if (!pwForm.value.oldPassword || !pwForm.value.newPassword) {
    ElMessage.warning('请填写完整')
    return
  }
  if (pwForm.value.newPassword.length < 6) {
    ElMessage.warning('新密码至少 6 位')
    return
  }
  if (pwForm.value.newPassword !== pwForm.value.confirmPassword) {
    ElMessage.warning('两次密码不一致')
    return
  }
  pwLoading.value = true
  try {
    await adminAPI.changePassword(pwForm.value.oldPassword, pwForm.value.newPassword)
    ElMessage.success('密码修改成功，请重新登录')
    showPasswordDialog.value = false
    setTimeout(() => handleLogout(), 1500)
  } catch (e: any) {
    ElMessage.error(e.response?.data?.error || '修改失败')
  } finally {
    pwLoading.value = false
  }
}
</script>

<style scoped>
.admin-layout {
  display: flex;
  min-height: 100vh;
  background: var(--bg-body);
}
.admin-sidebar {
  width: 240px;
  background: var(--bg-card);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  transition: width 0.3s;
  position: fixed;
  top: 0; left: 0; bottom: 0;
  z-index: 100;
}
.admin-sidebar.collapsed { width: 64px; }
.sidebar-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px;
  border-bottom: 1px solid var(--border-color);
}
.sidebar-logo { width: 28px; height: 28px; flex-shrink: 0; }
.sidebar-title { font-weight: 700; font-size: 16px; }
.sidebar-nav {
  flex: 1;
  padding: 16px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 14px;
  text-decoration: none;
  transition: all 0.2s;
  background: none;
  border: none;
  cursor: pointer;
  width: 100%;
  text-align: left;
}
.nav-item:hover { background: var(--bg-card-hover); color: var(--text-primary); }
.nav-item.active { background: rgba(0, 212, 170, 0.1); color: var(--sg-primary); }
.sidebar-footer {
  padding: 12px;
  border-top: 1px solid var(--border-color);
}
.logout { color: var(--sg-danger) !important; }

.admin-main {
  flex: 1;
  margin-left: 240px;
  transition: margin 0.3s;
  display: flex;
  flex-direction: column;
}
.admin-sidebar.collapsed ~ .admin-main { margin-left: 64px; }

.admin-topbar {
  height: 56px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--border-color);
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 0 24px;
  position: sticky;
  top: 0;
  z-index: 10;
}
.collapse-btn {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 20px;
  padding: 4px;
}
.page-title { font-size: 16px; font-weight: 600; }
.admin-content {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
}

@media (max-width: 768px) {
  .admin-sidebar { width: 64px; }
  .sidebar-title, .nav-item span { display: none; }
  .admin-main { margin-left: 64px; }
}
</style>
