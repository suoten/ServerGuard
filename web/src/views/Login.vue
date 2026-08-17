<template>
  <div class="login-container">
    <!-- 背景装饰光斑 -->
    <div class="bg-orb bg-orb-1"></div>
    <div class="bg-orb bg-orb-2"></div>
    <div class="bg-grid"></div>

    <div class="login-box sg-fade-in-up">
      <div class="logo">
        <div class="logo-ring">
          <img src="/favicon.svg" alt="ServerGuard" class="login-logo-icon" />
        </div>
        <h1>ServerGuard</h1>
        <p>服务器智能守护系统</p>
      </div>
      <el-form :model="form" @keyup.enter="handleLogin" label-position="top" class="login-form" size="large">
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="请输入用户名" prefix-icon="User" autocomplete="username" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" placeholder="请输入密码" show-password prefix-icon="Lock" autocomplete="current-password" />
        </el-form-item>
        <el-form-item style="margin-bottom: 0">
          <el-button type="primary" @click="handleLogin" :loading="loading" class="login-btn" size="large">
            {{ loading ? '登录中…' : '登 录' }}
          </el-button>
        </el-form-item>
      </el-form>
      <div class="login-footer">ServerGuard · 让服务器自己照顾自己</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { ElMessage } from 'element-plus'

const router = useRouter()
const loading = ref(false)

const form = reactive({
  username: '',
  password: '',
})

async function handleLogin() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  try {
    const resp = await axios.post('/api/login', {
      username: form.username,
      password: form.password,
    })
    const token = resp.data.token
    localStorage.setItem('sg_token', token)
    localStorage.setItem('sg_user', form.username)
    // Set default auth header for all future requests
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`
    ElMessage.success('登录成功')
    router.push('/dashboard')
  } catch (err: any) {
    const msg = err.response?.data?.error || '登录失败'
    ElMessage.error(msg)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  position: relative;
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #0d1424 0%, #16213c 55%, #1a2a52 100%);
  overflow: hidden;
}

/* ─── 背景装饰 ─── */
.bg-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 75%);
  -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 75%);
}
.bg-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(90px);
  opacity: 0.5;
  animation: orb-float 12s ease-in-out infinite;
}
.bg-orb-1 {
  width: 420px;
  height: 420px;
  top: -120px;
  right: -80px;
  background: radial-gradient(circle, rgba(76, 111, 255, 0.55), transparent 70%);
}
.bg-orb-2 {
  width: 360px;
  height: 360px;
  bottom: -120px;
  left: -60px;
  background: radial-gradient(circle, rgba(34, 197, 94, 0.28), transparent 70%);
  animation-delay: -6s;
}
@keyframes orb-float {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(-30px, 24px) scale(1.06); }
}

/* ─── 登录卡片：玻璃拟态 ─── */
.login-box {
  position: relative;
  z-index: 1;
  width: 400px;
  max-width: 92vw;
  padding: 44px 40px 28px;
  background: rgba(255, 255, 255, 0.97);
  border-radius: 20px;
  box-shadow: 0 24px 64px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(255, 255, 255, 0.1);
  box-sizing: border-box;
}

.login-form :deep(.el-form-item__label) {
  font-size: 13px;
  font-weight: 500;
  color: #475569;
  padding-bottom: 6px !important;
}
.login-form :deep(.el-input__wrapper) {
  padding: 4px 14px;
  border-radius: 10px;
}

.login-btn {
  width: 100%;
  margin-top: 8px;
  border-radius: 10px;
  font-size: 16px;
  letter-spacing: 0.3em;
  text-indent: 0.3em;
  font-weight: 600;
}

/* ─── Logo 区 ─── */
.logo {
  display: block;
  text-align: center;
  margin-bottom: 32px;
}
.logo-ring {
  width: 76px;
  height: 76px;
  margin: 0 auto 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 20px;
  background: linear-gradient(135deg, #eef1ff 0%, #dde3ff 100%);
  box-shadow: 0 8px 24px rgba(76, 111, 255, 0.28), inset 0 0 0 1px rgba(76, 111, 255, 0.15);
}
.login-logo-icon {
  width: 44px;
  height: 44px;
}
.logo h1 {
  display: block;
  font-size: 26px;
  color: #1e293b;
  margin: 0 0 6px 0;
  line-height: 1.2;
  letter-spacing: 0.01em;
}
.logo p {
  display: block;
  color: #94a3b8;
  font-size: 13px;
  margin: 0;
  letter-spacing: 0.14em;
}

.login-footer {
  margin-top: 26px;
  text-align: center;
  font-size: 12px;
  color: #b0b8c9;
  letter-spacing: 0.05em;
}

@media screen and (max-width: 480px) {
  .login-box {
    padding: 36px 24px 22px;
    border-radius: 16px;
  }
  .login-btn {
    letter-spacing: 0.2em;
    text-indent: 0.2em;
  }
}
</style>
