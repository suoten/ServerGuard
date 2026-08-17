import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// 插件：构建后去掉 script 标签上的 crossorigin 属性
// 避免浏览器对 ES Module 动态 import() 做 CORS 检查导致加载失败
function removeCrossorigin() {
  return {
    name: 'remove-crossorigin',
    transformIndexHtml: {
      enforce: 'post' as const,
      transform(html: string) {
        return html.replace(/<script([^>]*?)\scrossorigin/g, '<script$1')
      },
    },
  }
}

export default defineConfig({
  plugins: [vue(), removeCrossorigin()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 3200,
    proxy: {
      '/api': {
        target: 'http://localhost:8422',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1500,
  },
})
