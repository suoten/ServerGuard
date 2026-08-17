import { ref, watch } from 'vue'

// 全局共享的暗色状态（模块级单例，跨组件同步）
const isDark = ref(false)

function applyDark(dark: boolean) {
  document.documentElement.classList.toggle('dark', dark)
}

// 初始化：优先本地存储，其次跟随系统偏好
function initDark() {
  const saved = localStorage.getItem('sg_theme')
  if (saved === 'dark' || saved === 'light') {
    isDark.value = saved === 'dark'
  } else {
    isDark.value = window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
  }
  applyDark(isDark.value)
}

// 模块加载即初始化（保证首帧不闪烁）
initDark()

watch(isDark, (v) => {
  applyDark(v)
  localStorage.setItem('sg_theme', v ? 'dark' : 'light')
})

export function useDark() {
  function toggleDark() {
    isDark.value = !isDark.value
  }
  return { isDark, toggleDark }
}
