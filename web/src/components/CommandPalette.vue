<template>
  <teleport to="body">
    <transition name="cmdk-fade">
      <div v-if="modelValue" class="cmdk-overlay" @mousedown.self="close">
        <div class="cmdk-panel" role="dialog" aria-label="快捷命令面板">
          <div class="cmdk-input-row">
            <el-icon :size="16" class="cmdk-search-icon"><Search /></el-icon>
            <input
              ref="inputRef"
              v-model="keyword"
              class="cmdk-input"
              placeholder="搜索页面或命令…（↑↓ 选择，Enter 执行，Esc 关闭）"
              @keydown.down.prevent="move(1)"
              @keydown.up.prevent="move(-1)"
              @keydown.enter.prevent="run(filtered[activeIndex])"
              @keydown.esc.prevent="close"
            />
          </div>

          <div class="cmdk-list" ref="listRef">
            <template v-for="(group, gi) in grouped" :key="gi">
              <div class="cmdk-group">{{ group.label }}</div>
              <div
                v-for="item in group.items"
                :key="item.id"
                class="cmdk-item"
                :class="{ active: flatIndex(group.items, item) === activeIndex }"
                @mouseenter="activeIndex = flatIndex(group.items, item)"
                @click="run(item)"
              >
                <el-icon :size="15" class="cmdk-item-icon">
                  <component :is="item.icon" />
                </el-icon>
                <span class="cmdk-item-title">{{ item.title }}</span>
                <span v-if="item.hint" class="cmdk-item-hint">{{ item.hint }}</span>
              </div>
            </template>
            <div v-if="filtered.length === 0" class="cmdk-empty">没有匹配「{{ keyword }}」的命令</div>
          </div>

          <div class="cmdk-footer">
            <span><kbd>↑↓</kbd> 选择</span>
            <span><kbd>Enter</kbd> 执行</span>
            <span><kbd>Esc</kbd> 关闭</span>
          </div>
        </div>
      </div>
    </transition>
  </teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import {
  Search, Odometer, Monitor, Bell, Warning, DocumentChecked, Lock, Cpu, Key,
  Connection, FolderOpened, Compass, Document, Tickets, UserFilled, Finished,
  Setting, Sunny, Moon, SwitchButton, Position, Refresh, CircleClose, CircleCheck,
  Aim, Files, Collection, Guide, Tools, DataLine,
} from '@element-plus/icons-vue'
import { useDark } from '@/composables/useDark'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const router = useRouter()
const { isDark, toggleDark } = useDark()

const keyword = ref('')
const activeIndex = ref(0)
const inputRef = ref<HTMLInputElement | null>(null)
const listRef = ref<HTMLElement | null>(null)

interface Cmd {
  id: string
  group: 'nav' | 'action'
  title: string
  keywords: string
  icon: any
  hint?: string
  run: () => void | Promise<void>
}

const nav = (path: string, title: string, icon: any, keywords = ''): Cmd => ({
  id: 'nav-' + path,
  group: 'nav',
  title,
  keywords: (keywords + ' ' + title + ' ' + path).toLowerCase(),
  icon,
  run: () => { void router.push(path) },
})

const commands: Cmd[] = [
  // ─── 页面导航 ───
  nav('/dashboard', '仪表盘', Odometer, 'yibiaopan home 首页 概览'),
  nav('/servers', '服务器', Monitor, 'fuwuqi server 主机'),
  nav('/alerts', '告警中心', Bell, 'gaojing alert 告警'),
  nav('/findings', '安全扫描', Search, 'anquan faxian finding 基线'),
  nav('/attacks', '攻击预警', Warning, 'gongji attack 攻击'),
  nav('/rules', '规则管理', DocumentChecked, 'guize rule 规则'),
  nav('/safety', '安全控制', Lock, 'anquan kongzhi safety 维护窗口 熔断'),
  nav('/guards', '服务守护', Cpu, 'shouhu guard 守护 进程'),
  nav('/certs', '证书管理', Key, 'zhengshu cert 证书 ssl'),
  nav('/monitoring', '网站监控', Connection, 'wangzhan monitoring 监控 存活'),
  nav('/large-files', '磁盘与文件', FolderOpened, 'dawenjian large file 磁盘'),
  nav('/baota', '宝塔发现', Compass, 'baota bt 宝塔'),
  nav('/logs', '操作日志', Document, 'rizhi log 日志'),
  nav('/audit', '审计日志', Tickets, 'shenji audit 审计'),
  nav('/rbac', '用户角色', UserFilled, 'yonghu rbac 角色 权限'),
  nav('/config-approval', '配置审批', Finished, 'peizhi approval 审批'),
  nav('/settings', '系统设置', Setting, 'xitong setting 设置 通知'),
  nav('/incidents', '故障事件', Aim, 'guzhang incident 事件 根因 因果链'),
  nav('/knowledge', '知识库与报告', Collection, 'zhishiku knowledge 知识库 推荐 反复 报告'),
  nav('/devops', 'DevOps 运维', Tools, 'devops deploy 部署 webhook 构建清理 批处理'),
  nav('/data-governance', '数据治理', DataLine, 'shuju data govern 备份 敏感数据 死锁 归档'),
  nav('/onboarding', '初始化向导', Guide, 'onboarding xiangdao 向导 初始化'),

  // ─── 快捷操作 ───
  {
    id: 'action-theme',
    group: 'action',
    title: isDark.value ? '切换为浅色模式' : '切换为深色模式',
    keywords: 'theme dark light 深色 浅色 主题 模式 qiehuan',
    icon: isDark.value ? Sunny : Moon,
    hint: '立即切换',
    run: () => {
      toggleDark()
      ElMessage.success(isDark.value ? '已切换为深色模式' : '已切换为浅色模式')
    },
  },
  {
    id: 'action-refresh',
    group: 'action',
    title: '刷新当前页面数据',
    keywords: 'refresh shuaxin 刷新 重载',
    icon: Refresh,
    run: () => window.location.reload(),
  },
  {
    id: 'action-report',
    group: 'action',
    title: '立即发送每日巡检报告',
    keywords: 'report xunjian baogao 巡检 报告 推送',
    icon: Position,
    hint: '推送到所有渠道',
    run: async () => {
      try {
        await axios.post('/api/report/daily/send')
        ElMessage.success('巡检报告已推送到所有已启用渠道')
      } catch (err: any) {
        ElMessage.error(err.response?.data?.error || '发送失败')
      }
    },
  },
  {
    id: 'action-estop',
    group: 'action',
    title: '紧急停止所有自动修复',
    keywords: 'emergency stop jinji tingzhi 紧急 停止 熔断',
    icon: CircleClose,
    hint: '高危操作',
    run: async () => {
      try {
        await axios.post('/api/emergency-stop')
        ElMessage.warning('已紧急停止：系统只监控告警，不再自动修复')
      } catch {
        ElMessage.error('操作失败')
      }
    },
  },
  {
    id: 'action-eresume',
    group: 'action',
    title: '恢复自动修复',
    keywords: 'resume huifu 恢复 修复',
    icon: CircleCheck,
    run: async () => {
      try {
        await axios.post('/api/emergency-resume')
        ElMessage.success('已恢复自动修复')
      } catch {
        ElMessage.error('操作失败')
      }
    },
  },
  {
    id: 'action-logout',
    group: 'action',
    title: '退出登录',
    keywords: 'logout tuichu 退出 登出',
    icon: SwitchButton,
    run: () => {
      localStorage.removeItem('sg_token')
      localStorage.removeItem('sg_user')
      delete axios.defaults.headers.common['Authorization']
      void router.push('/login')
    },
  },
]

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  // 主题命令标题随状态动态变化，实时计算
  const list = commands.map((c) => {
    if (c.id === 'action-theme') {
      return { ...c, title: isDark.value ? '切换为浅色模式' : '切换为深色模式', icon: isDark.value ? Sunny : Moon }
    }
    return c
  })
  if (!kw) return list
  return list.filter((c) => c.keywords.includes(kw) || c.title.toLowerCase().includes(kw))
})

const grouped = computed(() => {
  const navs = filtered.value.filter((c) => c.group === 'nav')
  const acts = filtered.value.filter((c) => c.group === 'action')
  const groups: { label: string; items: Cmd[] }[] = []
  if (acts.length) groups.push({ label: '快捷操作', items: acts })
  if (navs.length) groups.push({ label: '页面导航', items: navs })
  return groups
})

function flatIndex(_items: Cmd[], item: Cmd): number {
  return filtered.value.indexOf(item)
}

function move(delta: number) {
  const n = filtered.value.length
  if (n === 0) return
  activeIndex.value = (activeIndex.value + delta + n) % n
  nextTick(() => {
    listRef.value?.querySelector('.cmdk-item.active')?.scrollIntoView({ block: 'nearest' })
  })
}

async function run(item: Cmd | undefined) {
  if (!item) return
  close()
  await item.run()
}

function close() {
  emit('update:modelValue', false)
}

watch(() => props.modelValue, async (v) => {
  if (v) {
    keyword.value = ''
    activeIndex.value = 0
    await nextTick()
    inputRef.value?.focus()
  }
})

watch(keyword, () => { activeIndex.value = 0 })
</script>

<style scoped>
.cmdk-overlay {
  position: fixed;
  inset: 0;
  z-index: 10000;
  background: rgba(15, 23, 42, 0.45);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding-top: 14vh;
}
.cmdk-panel {
  width: 560px;
  max-width: 92vw;
  background: var(--sg-bg-card);
  border: 1px solid var(--sg-border);
  border-radius: 14px;
  box-shadow: var(--sg-shadow-lg);
  overflow: hidden;
}
.cmdk-input-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--sg-border);
}
.cmdk-search-icon { color: var(--sg-text-3); flex-shrink: 0; }
.cmdk-input {
  flex: 1;
  border: none;
  outline: none;
  background: transparent;
  font-size: 15px;
  color: var(--sg-text-1);
  font-family: inherit;
}
.cmdk-input::placeholder { color: var(--sg-text-3); }

.cmdk-list {
  max-height: 46vh;
  overflow-y: auto;
  padding: 8px;
}
.cmdk-group {
  padding: 8px 10px 4px;
  font-size: 11px;
  font-weight: 600;
  color: var(--sg-text-3);
  letter-spacing: 0.08em;
}
.cmdk-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.1s;
}
.cmdk-item.active {
  background: linear-gradient(90deg, rgba(76, 111, 255, 0.12), rgba(76, 111, 255, 0.05));
}
.cmdk-item-icon { color: var(--sg-text-3); flex-shrink: 0; }
.cmdk-item.active .cmdk-item-icon { color: var(--sg-primary); }
.cmdk-item-title { flex: 1; font-size: 14px; color: var(--sg-text-1); }
.cmdk-item-hint { font-size: 12px; color: var(--sg-text-3); }
.cmdk-empty {
  padding: 28px 0;
  text-align: center;
  color: var(--sg-text-3);
  font-size: 13px;
}

.cmdk-footer {
  display: flex;
  gap: 16px;
  padding: 10px 16px;
  border-top: 1px solid var(--sg-border);
  font-size: 11px;
  color: var(--sg-text-3);
}
.cmdk-footer kbd {
  font-family: inherit;
  padding: 1px 5px;
  border: 1px solid var(--sg-border);
  border-bottom-width: 2px;
  border-radius: 4px;
  background: var(--sg-bg-page);
  margin-right: 3px;
}

.cmdk-fade-enter-active { transition: opacity 0.15s ease; }
.cmdk-fade-leave-active { transition: opacity 0.1s ease; }
.cmdk-fade-enter-from, .cmdk-fade-leave-to { opacity: 0; }
.cmdk-fade-enter-active .cmdk-panel { transition: transform 0.15s ease; }
.cmdk-fade-enter-from .cmdk-panel { transform: translateY(-8px) scale(0.98); }
</style>
