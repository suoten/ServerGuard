<template>
  <el-config-provider :locale="locale">
    <div v-if="isLoginPage">
      <router-view />
    </div>
    <div v-else class="app-container">
      <el-container>
        <el-aside :width="sidebarWidth" class="sidebar" :class="{ 'mobile-open': sidebarOpen, 'is-collapsed': menuCollapsed }">
          <div class="logo" :class="{ 'logo-collapsed': menuCollapsed }" title="回到仪表盘" @click="$router.push('/dashboard')">
            <img src="/favicon.svg" alt="ServerGuard" class="logo-icon" />
            <div v-show="!menuCollapsed" class="logo-text">
              <h2>ServerGuard</h2>
              <span class="logo-sub">服务器智能守护</span>
            </div>
          </div>
          <el-menu
            ref="menuRef"
            class="sidebar-menu"
            popper-class="sg-menu-popper"
            :default-active="activeMenu"
            router
            :collapse="menuCollapsed"
            :default-openeds="initialOpeneds"
            :collapse-transition="true"
          >
            <!-- 总览 -->
            <el-menu-item index="/dashboard">
              <el-icon><Odometer /></el-icon><span>仪表盘</span>
            </el-menu-item>
            <el-menu-item index="/servers">
              <el-icon><Monitor /></el-icon><span>服务器</span>
            </el-menu-item>

            <!-- 安全防护 -->
            <el-sub-menu index="security">
              <template #title>
                <el-icon><Lock /></el-icon><span>安全防护</span>
              </template>
              <el-menu-item index="/alerts">
                <el-icon><Bell /></el-icon><span>告警中心</span>
              </el-menu-item>
              <el-menu-item index="/attacks">
                <el-icon><Warning /></el-icon><span>攻击预警</span>
              </el-menu-item>
              <el-menu-item index="/findings">
                <el-icon><Search /></el-icon><span>安全扫描</span>
              </el-menu-item>
              <el-menu-item index="/safety">
                <el-icon><Lock /></el-icon><span>安全控制</span>
              </el-menu-item>
              <el-menu-item index="/rules">
                <el-icon><DocumentChecked /></el-icon><span>规则管理</span>
              </el-menu-item>
            </el-sub-menu>

            <!-- 运维管理 -->
            <el-sub-menu index="ops">
              <template #title>
                <el-icon><Tools /></el-icon><span>运维管理</span>
              </template>
              <el-menu-item index="/guards">
                <el-icon><Cpu /></el-icon><span>服务守护</span>
              </el-menu-item>
              <el-menu-item index="/certs">
                <el-icon><Key /></el-icon><span>证书管理</span>
              </el-menu-item>
              <el-menu-item index="/large-files">
                <el-icon><FolderOpened /></el-icon><span>磁盘与文件</span>
              </el-menu-item>
              <el-menu-item index="/monitoring">
                <el-icon><Connection /></el-icon><span>网站监控</span>
              </el-menu-item>
              <el-menu-item index="/baota">
                <el-icon><Compass /></el-icon><span>宝塔发现</span>
              </el-menu-item>
            </el-sub-menu>

            <!-- 智能运维 -->
            <el-sub-menu index="smart">
              <template #title>
                <el-icon><MagicStick /></el-icon><span>智能运维</span>
              </template>
              <el-menu-item index="/incidents">
                <el-icon><Aim /></el-icon><span>故障事件</span>
              </el-menu-item>
              <el-menu-item index="/apm">
                <el-icon><DataLine /></el-icon><span>APM 监控</span>
              </el-menu-item>
              <el-menu-item index="/devops">
                <el-icon><Tools /></el-icon><span>DevOps 运维</span>
              </el-menu-item>
              <el-menu-item index="/data-governance">
                <el-icon><DataLine /></el-icon><span>数据治理</span>
              </el-menu-item>
              <el-menu-item index="/netquality">
                <el-icon><MapLocation /></el-icon><span>网络质量</span>
              </el-menu-item>
              <el-menu-item index="/knowledge">
                <el-icon><Collection /></el-icon><span>知识库与报告</span>
              </el-menu-item>
              <el-menu-item index="/maintenance-window">
                <el-icon><Timer /></el-icon><span>变更窗口</span>
              </el-menu-item>
            </el-sub-menu>

            <!-- 系统 -->
            <el-sub-menu index="system">
              <template #title>
                <el-icon><Operation /></el-icon><span>系统</span>
              </template>
              <el-menu-item index="/logs">
                <el-icon><Document /></el-icon><span>操作日志</span>
              </el-menu-item>
              <el-menu-item index="/audit">
                <el-icon><Tickets /></el-icon><span>审计日志</span>
              </el-menu-item>
              <el-menu-item index="/rbac">
                <el-icon><UserFilled /></el-icon><span>用户角色</span>
              </el-menu-item>
              <el-menu-item index="/config-approval">
                <el-icon><Finished /></el-icon><span>配置审批</span>
              </el-menu-item>
              <el-menu-item index="/settings">
                <el-icon><Setting /></el-icon><span>系统设置</span>
              </el-menu-item>
            </el-sub-menu>
          </el-menu>
          <div class="sidebar-footer" :class="{ 'footer-collapsed': menuCollapsed }">
            <template v-if="!menuCollapsed">
              <span class="sg-dot sg-dot--pulse" style="background: #22c55e"></span>
              <span class="version-text">v{{ agentStatus?.version || '0.3.0' }}</span>
            </template>
            <el-tooltip :content="menuCollapsed ? '展开侧边栏 (Ctrl+B)' : '收起侧边栏 (Ctrl+B)'" placement="right">
              <button
                class="collapse-btn"
                :aria-label="menuCollapsed ? '展开侧边栏' : '收起侧边栏'"
                @click="toggleSidebar"
              >
                <el-icon :size="15" class="collapse-icon" :class="{ 'is-collapsed': menuCollapsed }">
                  <Fold />
                </el-icon>
              </button>
            </el-tooltip>
          </div>
        </el-aside>

        <!-- 移动端遮罩：点击关闭侧边栏 -->
        <div v-if="sidebarOpen" class="sidebar-backdrop" @click="sidebarOpen = false"></div>

        <el-container>
          <el-header class="header" height="60px">
            <div class="header-left">
              <el-icon class="mobile-menu-btn" :size="22" @click="sidebarOpen = true"><Menu /></el-icon>
              <span class="page-title">{{ pageTitle }}</span>
              <el-tag :type="modeTagType" size="small" effect="light" round>
                {{ modeLabel }}
              </el-tag>
              <el-tag v-if="emergencyStop" type="danger" size="small" effect="dark" round>
                紧急停止已激活
              </el-tag>
            </div>
            <div class="header-right">
              <!-- 命令面板触发 -->
              <div class="cmdk-trigger" @click="paletteOpen = true" title="快捷命令面板">
                <el-icon :size="14"><Search /></el-icon>
                <span class="cmdk-text">搜索 / 命令</span>
                <kbd class="cmdk-kbd">Ctrl K</kbd>
              </div>
              <!-- 深色模式切换 -->
              <el-tooltip :content="isDark ? '切换为浅色模式' : '切换为深色模式'" placement="bottom">
                <el-icon class="theme-toggle" :size="18" @click="toggleDark">
                  <Sunny v-if="isDark" />
                  <Moon v-else />
                </el-icon>
              </el-tooltip>
              <el-tooltip v-if="emergencyStop" content="恢复自动修复" placement="bottom">
                <el-button type="success" size="small" round @click="resumeEmergency">
                  恢复自动修复
                </el-button>
              </el-tooltip>
              <el-tooltip v-else content="一键停止所有自动修复" placement="bottom">
                <el-button type="danger" size="small" plain round @click="triggerEmergency">
                  紧急停止
                </el-button>
              </el-tooltip>
              <el-dropdown trigger="click" @command="onUserCommand">
                <div class="user-chip">
                  <span class="user-avatar">{{ username.charAt(0).toUpperCase() }}</span>
                  <span class="user-info">{{ username }}</span>
                  <el-icon class="user-caret" :size="12"><ArrowDown /></el-icon>
                </div>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item disabled>
                      <span style="color: #94a3b8">当前账号：{{ username }}</span>
                    </el-dropdown-item>
                    <el-dropdown-item divided command="logout">
                      <el-icon><SwitchButton /></el-icon>退出登录
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </div>
          </el-header>

          <el-main class="main-content">
            <!-- 维护窗口横幅 -->
            <el-alert
              v-if="maintenanceActive"
              type="warning"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
            >
              <template #title>维护窗口进行中 · 自动修复已暂停</template>
              <template #default>
                当前处于维护窗口期，ServerGuard 只监控告警、不执行任何自动修复，窗口到期后自动恢复。
                <el-button text type="primary" size="small" @click="$router.push('/safety')" style="margin-left: 4px">查看维护窗口</el-button>
              </template>
            </el-alert>

            <!-- 学习模式横幅 -->
            <el-alert
              v-if="learnMode"
              type="warning"
              :closable="false"
              show-icon
              style="margin-bottom: 16px"
            >
              <template #title>当前为学习模式，系统只观察不操作</template>
              <template #default>
                ServerGuard 正在学习你的服务器正常状态，此期间不会执行任何自动修复。
                <span v-if="learnRemainingDays > 0" style="margin-left: 8px; font-weight: bold">
                  预计 {{ learnRemainingDays }} 天后自动开启自动修复。
                </span>
                <span v-else style="margin-left: 8px">
                  学习期即将结束，重启后自动开启自动修复。
                </span>
              </template>
            </el-alert>

            <router-view v-slot="{ Component }">
              <transition name="page-fade" mode="out-in">
                <component :is="Component" />
              </transition>
            </router-view>
          </el-main>
        </el-container>
      </el-container>

      <!-- 紧急停止悬浮按钮（全局，常驻右下角） -->
      <el-tooltip content="紧急停止" placement="left">
        <el-button
          v-if="!emergencyStop && !isLoginPage"
          type="danger"
          circle
          size="large"
          class="emergency-stop-btn"
          @click="confirmEmergencyStop"
        >
          <el-icon :size="20"><WarningFilled /></el-icon>
        </el-button>
      </el-tooltip>

      <!-- 紧急停止确认弹窗 -->
      <el-dialog
        v-model="emergencyDialogVisible"
        title="紧急停止所有自动修复"
        width="440px"
        :close-on-click-modal="false"
      >
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 16px">
          停止后系统将只监控和告警，不再执行任何修复操作（如重启服务、清理磁盘、关闭进程等）。
        </el-alert>
        <p style="color: #606266; line-height: 1.8; margin-bottom: 12px">
          遇到异常情况时可手动触发。停止后可随时恢复。
        </p>
        <el-checkbox v-model="emergencyAck">我已了解停止后系统不会自动修复任何问题</el-checkbox>
        <template #footer>
          <el-button @click="emergencyDialogVisible = false">暂不停止</el-button>
          <el-button type="danger" :disabled="!emergencyAck" @click="doEmergencyStop">确认紧急停止</el-button>
        </template>
      </el-dialog>
    </div>

    <!-- Ctrl+K 快捷命令面板 -->
    <CommandPalette v-model="paletteOpen" />
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import axios from 'axios'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import {
  WarningFilled, Odometer, Monitor, Bell, Search, Warning, DocumentChecked,
  Lock, Cpu, Key, Connection, FolderOpened, Compass, Document, Tickets,
  UserFilled, Finished, Setting, Menu, ArrowDown, SwitchButton, Sunny, Moon,
  DataLine, Collection, MapLocation, Files, Timer,
  Tools, MagicStick, Operation, Fold, Link, Aim, Guide,
} from '@element-plus/icons-vue'
import { useOffline } from '@/composables/useOffline'
import { useDark } from '@/composables/useDark'
import CommandPalette from '@/components/CommandPalette.vue'

useOffline()
const { isDark, toggleDark } = useDark()

const paletteOpen = ref(false)

const router = useRouter()
const route = useRoute()

const activeMenu = computed(() => route.path || '/dashboard')
const agentStatus = ref<any>({})
const locale = ref(zhCn)
const sidebarOpen = ref(false)
const sidebarCollapsed = ref(localStorage.getItem('sg_sidebar_collapsed') === 'true')
const isMobile = ref(false)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const menuRef = ref<any>(null)
const menuCollapsed = computed(() => sidebarCollapsed.value && !isMobile.value)
const sidebarWidth = computed(() => menuCollapsed.value ? '64px' : '232px')

// 菜单分组与路由的映射，用于自动展开当前路由所在分组
const menuGroupMap: Record<string, string[]> = {
  security: ['/alerts', '/findings', '/attacks', '/rules', '/safety'],
  ops: ['/guards', '/certs', '/monitoring', '/large-files', '/baota'],
  smart: ['/apm', '/incidents', '/knowledge', '/devops', '/data-governance', '/netquality', '/maintenance-window'],
  system: ['/logs', '/audit', '/rbac', '/config-approval', '/settings'],
}

function getInitialOpeneds(): string[] {
  const path = route.path
  for (const [key, paths] of Object.entries(menuGroupMap)) {
    if (paths.includes(path)) return [key]
  }
  return []
}

const initialOpeneds = getInitialOpeneds()

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  localStorage.setItem('sg_sidebar_collapsed', String(sidebarCollapsed.value))
}

function checkMobile() {
  isMobile.value = window.innerWidth < 768
}

const username = ref(localStorage.getItem('sg_user') || 'admin')

// 同步设置 Authorization 头，确保在子组件创建前就生效
const savedToken = localStorage.getItem('sg_token')
if (savedToken) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${savedToken}`
}

const isLoginPage = computed(() => route.path === '/login')

// 页面标题映射（与菜单一致）
const pageTitles: Record<string, string> = {
  '/dashboard': '仪表盘', '/servers': '服务器', '/alerts': '告警中心',
  '/findings': '安全发现', '/attacks': '攻击预警', '/rules': '规则管理',
  '/safety': '安全控制', '/guards': '服务守护', '/certs': '证书管理',
  '/monitoring': '网站监控', '/large-files': '磁盘与文件', '/baota': '宝塔发现',
  '/logs': '操作日志', '/audit': '审计日志', '/rbac': '用户角色',
  '/config-approval': '配置审批', '/settings': '系统设置',
  '/apm': 'APM 监控', '/knowledge': '知识库与报告', '/netquality': '网络质量',
  '/maintenance-window': '变更窗口',
  '/incidents': '故障事件', '/onboarding': '快速接入',
  '/devops': 'DevOps 运维', '/data-governance': '数据治理',
}
const pageTitle = computed(() => pageTitles[route.path] || '')

const modeLabel = computed(() => {
  const mode = agentStatus.value?.mode || 'normal'
  const labels: Record<string, string> = {
    normal: '正常运行',
    throttled: '降频模式',
    minimal: '最小模式',
    survival: '存活模式',
    emergency: '紧急模式',
  }
  return labels[mode] || mode
})

const modeTagType = computed(() => {
  const mode = agentStatus.value?.mode || 'normal'
  return mode === 'normal' ? 'success' : 'warning'
})

const emergencyStop = computed(() => agentStatus.value?.emergency_stop || false)
const maintenanceActive = computed(() => agentStatus.value?.maintenance_active || false)
const learnMode = computed(() => agentStatus.value?.learn_mode || false)
const learnRemainingDays = computed(() => agentStatus.value?.learn_remaining_days || 0)
const emergencyDialogVisible = ref(false)
const emergencyAck = ref(false)

async function confirmEmergencyStop() {
  emergencyAck.value = false
  emergencyDialogVisible.value = true
}

async function doEmergencyStop() {
  try {
    await axios.post('/api/emergency-stop')
    await fetchStatus()
    emergencyDialogVisible.value = false
  } catch (err) {
    console.error('紧急停止失败:', err)
  }
}

async function fetchStatus() {
  try {
    const resp = await axios.get('/api/status')
    agentStatus.value = resp.data
  } catch (err) {
    console.error('获取状态失败:', err)
  }
}

async function triggerEmergency() {
  try {
    await axios.post('/api/emergency-stop')
    await fetchStatus()
  } catch (err) {
    console.error('紧急停止失败:', err)
  }
}

async function resumeEmergency() {
  try {
    await axios.post('/api/emergency-resume')
    await fetchStatus()
  } catch (err) {
    console.error('恢复失败:', err)
  }
}

function logout() {
  localStorage.removeItem('sg_token')
  localStorage.removeItem('sg_user')
  delete axios.defaults.headers.common['Authorization']
  router.push('/login')
}

function onUserCommand(cmd: string) {
  if (cmd === 'logout') logout()
}

// 路由切换后自动关闭移动端侧边栏 & 展开对应菜单分组
watch(() => route.path, (path) => {
  sidebarOpen.value = false
  // 自动展开当前路由所在的分组
  for (const [key, paths] of Object.entries(menuGroupMap)) {
    if (paths.includes(path)) {
      menuRef.value?.open(key)
    }
  }
  // 菜单较长时，将激活项滚动到可视区域
  nextTick(() => {
    document.querySelector('.sidebar-menu .el-menu-item.is-active')
      ?.scrollIntoView({ block: 'nearest' })
  })
})

let statusTimer: ReturnType<typeof setInterval> | null = null

// Ctrl+K / Cmd+K 打开命令面板；Ctrl+B 切换侧边栏折叠
function onGlobalKeydown(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    paletteOpen.value = !paletteOpen.value
  } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
    e.preventDefault()
    if (!isMobile.value) toggleSidebar()
  }
}

// Global axios interceptor: auto-logout on 401
axios.interceptors.response.use(
  (resp) => resp,
  (err) => {
    if (err?.response?.status === 401 && !isLoginPage.value) {
      localStorage.removeItem('sg_token')
      localStorage.removeItem('sg_user')
      delete axios.defaults.headers.common['Authorization']
      if (statusTimer) { clearInterval(statusTimer); statusTimer = null }
      router.push('/login')
    }
    return Promise.reject(err)
  }
)

onMounted(() => {
  window.addEventListener('keydown', onGlobalKeydown)
  checkMobile()
  window.addEventListener('resize', checkMobile)
  if (!isLoginPage.value) {
    fetchStatus()
    statusTimer = setInterval(fetchStatus, 15000)
  }
})

onUnmounted(() => {
  window.removeEventListener('keydown', onGlobalKeydown)
  window.removeEventListener('resize', checkMobile)
  if (statusTimer) { clearInterval(statusTimer); statusTimer = null }
})
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
.app-container { height: 100vh; }

/* ═══ 侧边栏：深色渐变 + 分组导航 ═══ */
.sidebar {
  background: linear-gradient(180deg, var(--sg-sidebar-bg-1) 0%, var(--sg-sidebar-bg-2) 100%);
  overflow: hidden; /* 菜单区独立滚动，logo/footer 固定 */
  display: flex;
  flex-direction: column;
  border-right: none !important;
  transition: width 0.28s cubic-bezier(0.4, 0, 0.2, 1);
}
.logo {
  padding: 20px 18px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  cursor: pointer;
  transition: padding 0.28s var(--sg-ease);
}
.logo:hover .logo-icon {
  filter: drop-shadow(0 2px 12px rgba(76, 111, 255, 0.85));
  transform: scale(1.06);
}
.logo-icon {
  width: 36px;
  height: 36px;
  filter: drop-shadow(0 2px 8px rgba(76, 111, 255, 0.5));
  transition: filter var(--sg-normal), transform var(--sg-normal);
}
.logo-text { display: flex; flex-direction: column; }
.logo.logo-collapsed {
  padding: 18px 0;
  justify-content: center;
}
.logo-collapsed .logo-icon {
  width: 32px;
  height: 32px;
}
.logo-text h2 {
  font-size: 17px;
  margin: 0;
  color: #fff;
  letter-spacing: 0.02em;
  line-height: 1.2;
}
.logo-sub {
  font-size: 11px;
  color: var(--sg-sidebar-text);
  margin-top: 2px;
  letter-spacing: 0.08em;
}

/* 菜单 */
.sidebar-menu.el-menu {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  background: transparent;
  border-right: none;
  padding: 8px 10px 16px;
  --el-menu-text-color: var(--sg-sidebar-text);
  --el-menu-hover-bg-color: rgba(255, 255, 255, 0.06);
  --el-menu-active-color: #fff;
  --el-menu-item-height: 42px;
}
.menu-group-title {
  padding: 16px 12px 6px;
  font-size: 11px;
  font-weight: 600;
  color: rgba(139, 152, 184, 0.6);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  user-select: none;
}
.sidebar-menu .el-menu-item {
  border-radius: 8px;
  margin: 2px 0;
  color: var(--sg-sidebar-text);
  transition: background var(--sg-fast), color var(--sg-fast), transform var(--sg-fast);
}
.sidebar-menu .el-menu-item:hover {
  background: rgba(255, 255, 255, 0.07);
  color: #d5dcee;
}
.sidebar-menu .el-menu-item.is-active {
  background: linear-gradient(90deg, var(--sg-primary) 0%, var(--sg-primary-dark) 100%);
  color: #fff;
  font-weight: 600;
  box-shadow: 0 4px 12px rgba(76, 111, 255, 0.35);
}
.sidebar-menu .el-menu-item .el-icon {
  font-size: 17px;
}

/* ─── 子菜单标题 ─── */
.sidebar-menu .el-sub-menu__title {
  border-radius: 8px;
  margin: 2px 0;
  color: var(--sg-sidebar-text);
  height: 42px;
  line-height: 42px;
  transition: background var(--sg-fast), color var(--sg-fast);
}
.sidebar-menu .el-sub-menu__title:hover {
  background: rgba(255, 255, 255, 0.07);
  color: #d5dcee;
}
.sidebar-menu .el-sub-menu__title .el-icon {
  font-size: 17px;
  color: var(--sg-sidebar-text);
}
.sidebar-menu .el-sub-menu__title .el-sub-menu__icon-arrow {
  color: rgba(139, 152, 184, 0.5);
}

/* ─── 子菜单项 ─── */
.sidebar-menu .el-sub-menu .el-menu-item {
  height: 38px;
  line-height: 38px;
  font-size: 13px;
  padding-left: 52px !important;
  min-width: auto;
}

/* ─── 折叠弹出子菜单（popper teleport 到 body，必须用全局 popper-class 选择器）─── */
.sg-menu-popper.el-popper {
  background: var(--sg-sidebar-bg-2) !important;
  border: 1px solid rgba(255, 255, 255, 0.1) !important;
  border-radius: 12px !important;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45) !important;
}
.sg-menu-popper .el-popper__arrow::before {
  background: var(--sg-sidebar-bg-2) !important;
  border-color: rgba(255, 255, 255, 0.1) !important;
}
.sg-menu-popper .el-menu--popup {
  background: transparent;
  padding: 6px;
  min-width: 168px;
}
.sg-menu-popper .el-menu-item {
  color: var(--sg-sidebar-text);
  border-radius: 8px;
  height: 38px;
  line-height: 38px;
  padding: 0 14px !important;
  min-width: auto;
  margin: 2px 0;
  transition: background var(--sg-fast), color var(--sg-fast);
}
.sg-menu-popper .el-menu-item:hover {
  background: rgba(255, 255, 255, 0.07);
  color: #d5dcee;
}
.sg-menu-popper .el-menu-item.is-active {
  background: linear-gradient(90deg, var(--sg-primary) 0%, var(--sg-primary-dark) 100%);
  color: #fff;
  font-weight: 600;
  box-shadow: 0 4px 12px rgba(76, 111, 255, 0.3);
}

/* ─── 折叠状态：菜单项居中大圆角块 ─── */
.sidebar-menu.el-menu--collapse {
  width: 64px;
}
.sidebar-menu.el-menu--collapse .el-menu-item,
.sidebar-menu.el-menu--collapse .el-sub-menu__title {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 0 !important;
  height: 44px;
  margin: 4px 0;
  border-radius: 10px;
}
.sidebar-menu.el-menu--collapse .el-menu-item .el-icon,
.sidebar-menu.el-menu--collapse .el-sub-menu__title .el-icon {
  font-size: 19px;
  margin-right: 0;
}

.sidebar-footer {
  margin-top: auto;
  padding: 14px 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}
.version-text { color: var(--sg-sidebar-text); font-size: 12px; white-space: nowrap; overflow: visible; }

/* ─── 折叠/展开按钮 ─── */
.collapse-btn {
  cursor: pointer;
  color: var(--sg-sidebar-text);
  width: 30px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.04);
  transition: all var(--sg-fast);
}
.collapse-btn:hover {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
  border-color: rgba(255, 255, 255, 0.2);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
.collapse-icon {
  transition: transform 0.28s var(--sg-ease);
}
.collapse-icon.is-collapsed {
  transform: rotate(180deg);
}
.sidebar-footer.footer-collapsed {
  padding: 14px 0;
  justify-content: center;
}

/* 移动端遮罩 */
.sidebar-backdrop {
  display: none;
}

/* ═══ 顶栏：毛玻璃 + 吸顶 ═══ */
.header {
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--sg-border);
  box-shadow: var(--sg-shadow-sm);
}
html.dark .header {
  background: rgba(21, 31, 51, 0.85);
}
.header-left { display: flex; align-items: center; gap: 10px; }
.header-right { display: flex; align-items: center; gap: 12px; }

/* 命令面板触发器 */
.cmdk-trigger {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 6px 10px;
  border: 1px solid var(--sg-border);
  border-radius: 8px;
  cursor: pointer;
  color: var(--sg-text-3);
  background: var(--sg-bg-card);
  transition: all var(--sg-fast);
  user-select: none;
}
.cmdk-trigger:hover {
  border-color: var(--sg-primary-light);
  color: var(--sg-text-2);
  box-shadow: var(--sg-shadow-sm);
}
.cmdk-text { font-size: 12px; }
.cmdk-kbd {
  font-family: inherit;
  font-size: 11px;
  padding: 1px 6px;
  border: 1px solid var(--sg-border);
  border-bottom-width: 2px;
  border-radius: 5px;
  background: var(--sg-bg-page);
  color: var(--sg-text-3);
}
/* 主题切换 */
.theme-toggle {
  cursor: pointer;
  color: var(--sg-text-2);
  padding: 7px;
  border-radius: 8px;
  transition: all var(--sg-fast);
}
.theme-toggle:hover {
  background: var(--sg-bg-page);
  color: var(--sg-primary);
}
.page-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--sg-text-1);
  margin-right: 4px;
}
.mobile-menu-btn {
  display: none;
  cursor: pointer;
  color: var(--sg-text-2);
  padding: 6px;
  border-radius: 6px;
  transition: background var(--sg-fast);
}
.mobile-menu-btn:hover { background: #eef1f7; }
html.dark .mobile-menu-btn:hover { background: #1d2947; }

/* 用户胶囊 */
.user-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 10px 5px 5px;
  border-radius: 999px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all var(--sg-fast);
  outline: none;
}
.user-chip:hover {
  background: #f3f5fa;
  border-color: var(--sg-border);
}
html.dark .user-chip:hover {
  background: #1d2947;
}
.user-avatar {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--sg-primary), var(--sg-primary-dark));
  color: #fff;
  font-size: 13px;
  font-weight: 700;
  box-shadow: var(--sg-shadow-primary);
}
.user-info { color: var(--sg-text-2); font-size: 14px; font-weight: 500; }
.user-caret { color: var(--sg-text-3); }

/* ═══ 主内容区 ═══ */
.main-content {
  padding: 20px;
  background: var(--sg-bg-page);
  overflow-y: auto;
}

/* ═══ 紧急停止悬浮按钮 ═══ */
.emergency-stop-btn {
  position: fixed;
  right: 24px;
  bottom: 24px;
  z-index: 9999;
  width: 56px;
  height: 56px;
  box-shadow: 0 4px 20px rgba(239, 68, 68, 0.45);
  animation: emergency-pulse 2s ease-in-out infinite;
}
.emergency-stop-btn:hover {
  transform: scale(1.06);
  box-shadow: 0 6px 28px rgba(239, 68, 68, 0.6);
}
@keyframes emergency-pulse {
  0%, 100% { box-shadow: 0 4px 20px rgba(239, 68, 68, 0.45); }
  50% { box-shadow: 0 4px 24px rgba(239, 68, 68, 0.75); }
}

/* ═══ 移动端适配补充 ═══ */
@media screen and (max-width: 767px) {
  .sidebar {
    width: 232px !important;
  }
  .mobile-menu-btn { display: inline-flex; }
  .page-title { font-size: 15px; }
  .cmdk-text, .cmdk-kbd { display: none; }
  .cmdk-trigger { padding: 7px; }
  .sidebar-backdrop {
    display: block;
    position: fixed;
    inset: 0;
    z-index: 99;
    background: rgba(15, 23, 42, 0.5);
    backdrop-filter: blur(2px);
    animation: sg-fade-in-up 0.2s ease both;
  }
}
</style>
