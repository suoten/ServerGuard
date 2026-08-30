import { ref, watch, onMounted, onUnmounted, type Ref } from 'vue'

/**
 * 数字递增动画 composable
 * 当目标值变化时，从当前值平滑递增到目标值
 *
 * @param target 目标值的 ref
 * @param duration 动画时长（毫秒），默认 800
 * @returns 动画显示值的 ref
 */
export function useCountUp(target: Ref<number>, duration = 800): Ref<number> {
  const display = ref(0)
  let rafId: number | null = null
  let startTime: number | null = null
  let startValue = 0

  function animate(toValue: number) {
    if (rafId !== null) {
      cancelAnimationFrame(rafId)
    }

    // 值为 0 或很小时直接设置，不动画
    if (toValue === 0) {
      display.value = 0
      return
    }

    // 值没变化，不动画
    if (toValue === display.value) return

    startValue = display.value
    startTime = null

    const step = (timestamp: number) => {
      if (startTime === null) {
        startTime = timestamp
      }
      const elapsed = timestamp - startTime
      const progress = Math.min(elapsed / duration, 1)

      // easeOutQuart：先快后慢，更自然
      const eased = 1 - Math.pow(1 - progress, 4)

      display.value = Math.round(startValue + (toValue - startValue) * eased)

      if (progress < 1) {
        rafId = requestAnimationFrame(step)
      }
    }

    rafId = requestAnimationFrame(step)
  }

  onMounted(() => {
    animate(target.value)
  })

  watch(target, (newVal) => {
    animate(newVal)
  })

  onUnmounted(() => {
    if (rafId !== null) {
      cancelAnimationFrame(rafId)
    }
  })

  return display
}
