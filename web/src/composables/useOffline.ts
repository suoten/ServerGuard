import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'

const isOnline = ref(true)
const offlineQueue: Array<{ url: string; method: string; data: any; resolve: Function; reject: Function }> = []

let warningShown = false

/**
 * 离线/弱网处理 composable
 * - 监听 online/offline 事件
 * - 断网时显示提示
 * - 网络恢复后自动重放离线操作队列
 */
export function useOffline() {
  function handleOffline() {
    isOnline.value = false
    if (!warningShown) {
      ElMessage.warning('当前离线，数据可能不是最新的')
      warningShown = true
    }
  }

  function handleOnline() {
    isOnline.value = true
    warningShown = false
    if (offlineQueue.length > 0) {
      ElMessage.success('网络已恢复，正在同步离线操作...')
      replayQueue()
    }
  }

  function replayQueue() {
    const queue = [...offlineQueue]
    offlineQueue.length = 0

    queue.forEach(async (item) => {
      try {
        const resp = await axios({
          url: item.url,
          method: item.method,
          data: item.data,
        })
        item.resolve(resp)
      } catch (err) {
        item.reject(err)
      }
    })
  }

  onMounted(() => {
    window.addEventListener('offline', handleOffline)
    window.addEventListener('online', handleOnline)
  })

  onUnmounted(() => {
    window.removeEventListener('offline', handleOffline)
    window.removeEventListener('online', handleOnline)
  })

  return {
    isOnline,
  }
}

/**
 * 将操作加入离线队列（用于关键操作如确认告警）
 */
export function enqueueOffline(url: string, method: string, data: any): Promise<any> {
  if (isOnline.value) {
    // 在线时直接执行
    return axios({ url, method, data })
  }
  // 离线时加入队列
  return new Promise((resolve, reject) => {
    offlineQueue.push({ url, method, data, resolve, reject })
    ElMessage.info('当前离线，操作将在网络恢复后自动同步')
  })
}
