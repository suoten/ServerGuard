<template>
  <DefaultLayout>
    <section class="not-found">
      <div class="container">
        <div class="nf-content">
          <h1 class="nf-code">404</h1>
          <p class="nf-msg">页面不存在或已被移动</p>
          <router-link to="/" class="btn btn-primary btn-lg">
            返回首页
          </router-link>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import DefaultLayout from '@/components/DefaultLayout.vue'
</script>

<style scoped>
.not-found {
  min-height: 60vh;
  display: flex;
  align-items: center;
  justify-content: center;
}
.nf-content { text-align: center; }
.nf-code {
  font-size: 120px;
  font-weight: 800;
  line-height: 1;
}
.nf-msg {
  color: var(--text-secondary);
  font-size: 18px;
  margin-bottom: 32px;
}
</style>
