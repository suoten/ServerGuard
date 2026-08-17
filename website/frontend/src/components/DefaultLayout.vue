<template>
  <div class="layout-wrapper">
    <WebsiteHeader />
    <main class="main-content">
      <slot />
    </main>
    <WebsiteFooter />
  </div>
</template>

<script setup lang="ts">
import WebsiteHeader from './WebsiteHeader.vue'
import WebsiteFooter from './WebsiteFooter.vue'
</script>

<style scoped>
.layout-wrapper {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.main-content {
  flex: 1;
  padding-top: var(--header-height);
}
</style>
