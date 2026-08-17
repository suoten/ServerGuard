<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-header">
        <svg class="login-logo" viewBox="0 0 32 32" fill="none">
          <path d="M16 2L4 7v9c0 7 5.2 12.8 12 14 6.8-1.2 12-7 12-14V7L16 2z"
            stroke="url(#lg2)" stroke-width="2" fill="rgba(0,212,170,0.08)"/>
          <path d="M11 16l3.5 3.5L21 13" stroke="url(#lg2)" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
          <defs>
            <linearGradient id="lg2" x1="0" y1="0" x2="32" y2="32">
              <stop stop-color="#00d4aa"/><stop offset="1" stop-color="#00b894"/>
            </linearGradient>
          </defs>
        </svg>
        <h1>ServerGuard 管理后台</h1>
        <p>请登录以管理网站内容</p>
      </div>
      <el-form :model="form" @submit.prevent="handleLogin" class="login-form">
        <el-form-item>
          <el-input
            v-model="form.username"
            placeholder="用户名"
            size="large"
            prefix-icon="User"
          />
        </el-form-item>
        <el-form-item>
          <el-input
            v-model="form.password"
            type="password"
            placeholder="密码"
            size="large"
            prefix-icon="Lock"
            show-password
            @keyup.enter="handleLogin"
          />
        </el-form-item>
        <el-button
          type="primary"
          size="large"
          class="login-btn"
          :loading="loading"
          @click="handleLogin"
        >
          登录
        </el-button>
      </el-form>
      <router-link to="/" class="back-home">← 返回官网首页</router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { adminAPI } from '@/composables/useAPI'

const router = useRouter()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

const handleLogin = async () => {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const resp = await adminAPI.login(form.username, form.password)
    localStorage.setItem('sg_admin_token', resp.data.token)
    ElMessage.success('登录成功')
    router.push('/admin')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '登录失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--gradient-hero);
  padding: 20px;
}
.login-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 48px 40px;
  width: 100%;
  max-width: 420px;
}
.login-header {
  text-align: center;
  margin-bottom: 32px;
}
.login-logo { width: 48px; height: 48px; }
.login-header h1 { font-size: 22px; margin: 16px 0 4px; }
.login-header p { color: var(--text-secondary); font-size: 14px; }
.login-form { margin-bottom: 24px; }
.login-btn { width: 100%; }
.back-home {
  display: block;
  text-align: center;
  color: var(--text-muted);
  font-size: 14px;
}
</style>
