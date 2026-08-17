<template>
  <div class="attack-page">
    <!-- 攻击事件流（自动检测） -->
    <el-card style="margin-bottom: 20px">
      <template #header>
        <div class="card-header">
          <span>攻击事件流 <el-tag size="small" type="info">共 {{ events.length }} 条</el-tag></span>
          <div class="header-actions">
            <el-input v-model="searchQuery" placeholder="搜索IP/类型/详情..." size="small" clearable style="width: 200px" :prefix-icon="Search" />
            <el-button :type="sortBySeverity ? 'danger' : 'default'" size="small" plain @click="sortBySeverity = !sortBySeverity">
              {{ sortBySeverity ? '🔴 按严重程度' : '🕐 按时间' }}
            </el-button>
            <el-tag type="success" size="small">每 5 分钟自动扫描</el-tag>
            <el-button type="success" size="small" @click="triggerScan" :loading="scanning">立即扫描</el-button>
            <el-button type="danger" size="small" @click="emergencyRollback">紧急回滚所有封禁</el-button>
          </div>
        </div>
      </template>
      <el-table :data="pagedEvents" stripe v-loading="loadingEvents" style="width: 100%" max-height="500">
        <el-table-column prop="source_ip" label="源 IP" width="180">
          <template #default="{ row }">
            <div>
              <span>{{ row.source_ip }}</span>
              <span v-if="ipLocationCache[row.source_ip]" style="color: #67c23a; font-size: 12px; margin-left: 6px">📍 {{ ipLocationCache[row.source_ip] }}</span>
              <el-button v-if="!isPrivateIP(row.source_ip) && !ipLocationCache[row.source_ip]" text size="small" @click="lookupIP(row.source_ip)" :loading="ipLookupIP === row.source_ip">
                查询属地
              </el-button>
              <span v-else-if="isPrivateIP(row.source_ip)" style="color: #909399; font-size: 12px; margin-left: 6px">内网</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="event_type" label="攻击类型" width="140">
          <template #default="{ row }">
            <el-tag :type="attackTypeColor(row.event_type)" size="small">{{ attackTypeLabel(row.event_type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="severityType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
          </template>
        </el-table-column>
<el-table-column prop="detail" label="详情" min-width="300" show-overflow-tooltip>
<template #default="{ row }">
<el-link type="primary" @click="showAttackDetail(row)">{{ formatDetail(row.detail) }}</el-link>
</template>
</el-table-column>
        <el-table-column prop="action_taken" label="处置" width="140">
          <template #default="{ row }">
            <el-tag :type="actionType(row.action_taken)" size="small">{{ actionLabel(row.action_taken) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="时间" width="180">
          <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
        </el-table-column>
        <template #empty>
          <div style="padding: 30px 0; text-align: center">
            <el-icon style="font-size: 32px; color: #c0c4cc; margin-bottom: 10px"><Loading /></el-icon>
            <p style="color: #909399; margin: 0">Agent 正在自动检测攻击事件，请稍候...</p>
            <p style="color: #c0c4cc; font-size: 12px; margin-top: 8px">检测到攻击后会自动显示并封禁恶意 IP</p>
          </div>
        </template>
      </el-table>
      <!-- 分页 -->
      <div style="margin-top: 16px; display: flex; justify-content: flex-end" v-if="events.length > 0">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          :total="filteredEvents.length"
          layout="total, sizes, prev, pager, next, jumper"
        />
      </div>
    </el-card>

    <!-- 攻击画像 + 封禁列表 -->
    <el-row :gutter="20">
      <el-col :span="14">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>攻击画像（源 IP 聚合）</span>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-input v-model="profileSearch" placeholder="搜索IP/类型..." size="small" clearable style="width: 160px" :prefix-icon="Search" />
                <el-tag type="info" size="small">近30天</el-tag>
              </div>
            </div>
          </template>
          <el-table :data="pagedProfiles" stripe v-loading="loadingProfiles" style="width: 100%" max-height="400">
            <el-table-column prop="source_ip" label="源 IP" width="150">
              <template #default="{ row }">
                {{ row.source_ip }}
                <el-tag v-if="isPersistent(row)" type="danger" size="small" style="margin-left:4px" title="长期/多类型攻击的持久攻击者，封禁已升级">持久</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="total_attacks" label="攻击次数" width="90" />
            <el-table-column prop="threat_level" label="威胁等级" width="100">
              <template #default="{ row }">
                <el-tag :type="threatType(row.threat_level)" size="small">{{ threatLabel(row.threat_level) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="attack_types" label="攻击类型" show-overflow-tooltip>
          <template #default="{ row }">
            {{ formatAttackTypes(row.attack_types) }}
          </template>
        </el-table-column>
            <el-table-column prop="first_seen" label="首次发现" width="160">
              <template #default="{ row }">{{ formatTime(row.first_seen) }}</template>
            </el-table-column>
            <el-table-column prop="last_seen" label="最近活动" width="160">
              <template #default="{ row }">{{ formatTime(row.last_seen) }}</template>
            </el-table-column>
            <template #empty>
              <p style="color: #909399; padding: 20px 0">暂无攻击画像数据</p>
            </template>
          </el-table>
          <div v-if="filteredProfiles.length > 10" style="margin-top: 12px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="profilesPage"
              v-model:page-size="profilesPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="filteredProfiles.length"
              layout="total, sizes, prev, pager, next"
              size="small"
            />
          </div>
        </el-card>
      </el-col>
      <el-col :span="10">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>已封禁 IP 列表</span>
              <div style="display: flex; align-items: center; gap: 10px">
                <el-input v-model="bannedSearch" placeholder="搜索IP..." size="small" clearable style="width: 120px" :prefix-icon="Search" />
                <el-button type="danger" size="small" plain @click="emergencyRollback">全部解封</el-button>
              </div>
            </div>
          </template>
          <el-table :data="pagedBanned" stripe v-loading="loadingBanned" style="width: 100%" max-height="400">
            <el-table-column prop="source_ip" label="IP 地址" width="140" />
            <el-table-column prop="event_type" label="封禁原因" show-overflow-tooltip>
              <template #default="{ row }">{{ attackTypeLabel(row.event_type) }}</template>
            </el-table-column>
            <el-table-column prop="severity" label="严重程度" width="90">
              <template #default="{ row }">
                <el-tag :type="severityType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="created_at" label="封禁时间" width="160">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <template #empty>
              <p style="color: #909399; padding: 20px 0">暂无封禁 IP</p>
            </template>
          </el-table>
          <div v-if="filteredBanned.length > 10" style="margin-top: 12px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="bannedPage"
              v-model:page-size="bannedSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="filteredBanned.length"
              layout="total, sizes, prev, pager, next"
              size="small"
            />
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 攻击详情对话框 -->
    <el-dialog v-model="attackDetailVisible" title="攻击详情" width="700px">
      <el-descriptions :column="1" border v-if="currentAttack">
        <el-descriptions-item label="攻击类型">{{ attackTypeLabel(currentAttack.event_type) }}</el-descriptions-item>
        <el-descriptions-item label="源 IP">{{ currentAttack.source_ip }}</el-descriptions-item>
        <el-descriptions-item label="严重程度">{{ severityLabel(currentAttack.severity) }}</el-descriptions-item>
        <el-descriptions-item label="处置方式">{{ actionLabel(currentAttack.action_taken) }}</el-descriptions-item>
        <el-descriptions-item label="目标">{{ currentAttack.target || '-' }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatTime(currentAttack.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="详情">{{ currentAttack.detail }}</el-descriptions-item>
        <el-descriptions-item label="追踪 ID">{{ currentAttack.trace_id || '-' }}</el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="attackDetailVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Loading, Search } from '@element-plus/icons-vue'
import axios from 'axios'
import dayjs from 'dayjs'
import { useRouter } from 'vue-router'

const router = useRouter()

const events = ref<any[]>([])
const profiles = ref<any[]>([])
const bannedIPs = ref<any[]>([])
const loadingEvents = ref(false)
const loadingProfiles = ref(false)
const loadingBanned = ref(false)
const scanning = ref(false)
const ipLookupIP = ref('')
const ipLocationCache = ref<Record<string, string>>({})
const searchQuery = ref('')
const profileSearch = ref('')
const bannedSearch = ref('')
const currentPage = ref(1)
const pageSize = ref(10)
const profilesPage = ref(1)
const profilesPageSize = ref(10)
const bannedPage = ref(1)
const bannedSize = ref(10)
const attackDetailVisible = ref(false)
const currentAttack = ref<any>(null)
const sortBySeverity = ref(true)
let refreshTimer: ReturnType<typeof setInterval> | null = null

const severityOrder: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1
}

const filteredEvents = computed(() => {
  let result = events.value
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter((e: any) =>
      e.source_ip?.toLowerCase().includes(q) ||
      e.event_type?.toLowerCase().includes(q) ||
      e.detail?.toLowerCase().includes(q)
    )
  }
  if (sortBySeverity.value) {
    result = [...result].sort((a: any, b: any) => {
      const diff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0)
      if (diff !== 0) return diff
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })
  }
  return result
})
const pagedEvents = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredEvents.value.slice(start, start + pageSize.value)
})
const filteredProfiles = computed(() => {
  let result = profiles.value
  if (profileSearch.value) {
    const q = profileSearch.value.toLowerCase()
    result = result.filter((p: any) =>
      p.source_ip?.toLowerCase().includes(q) ||
      p.attack_types?.toLowerCase().includes(q)
    )
  }
  if (sortBySeverity.value) {
    result = [...result].sort((a: any, b: any) => {
      const diff = (severityOrder[b.threat_level] || 0) - (severityOrder[a.threat_level] || 0)
      if (diff !== 0) return diff
      return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()
    })
  }
  return result
})
const pagedProfiles = computed(() => {
const start = (profilesPage.value - 1) * profilesPageSize.value
return filteredProfiles.value.slice(start, start + profilesPageSize.value)
})
const filteredBanned = computed(() => {
  let result = bannedIPs.value
  if (bannedSearch.value) {
    const q = bannedSearch.value.toLowerCase()
    result = result.filter((b: any) =>
      b.source_ip?.toLowerCase().includes(q) ||
      b.event_type?.toLowerCase().includes(q)
    )
  }
  if (sortBySeverity.value) {
    result = [...result].sort((a: any, b: any) => {
      const diff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0)
      if (diff !== 0) return diff
      return new Date(b.timestamp || b.created_at).getTime() - new Date(a.timestamp || a.created_at).getTime()
    })
  }
  return result
})
const pagedBanned = computed(() => {
  const start = (bannedPage.value - 1) * bannedSize.value
  return filteredBanned.value.slice(start, start + bannedSize.value)
})

const isPrivateIP = (ip: string) => {
  if (!ip) return false
  if (ip === '127.0.0.1' || ip === '::1') return true
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true
  if (ip.startsWith('172.')) {
    const parts = ip.split('.')
    const second = parseInt(parts[1])
    if (second >= 16 && second <= 31) return true
  }
  return false
}

const severityType = (s: string) => {
  const map: Record<string, string> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' }
  return map[s] || 'info'
}
const severityLabel = (s: string) => {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  return map[s] || s
}
const attackTypeColor = (t: string) => {
  if (!t) return 'info'
  if (t.includes('sql') || t.includes('xss') || t.includes('webshell')) return 'danger'
  if (t.includes('ssh') || t.includes('brute')) return 'warning'
  if (t.includes('scan') || t.includes('ddos')) return 'danger'
  return 'info'
}
const attackTypeLabel = (t: string) => {
  if (!t) return '未知'
  const map: Record<string, string> = {
    'sql_injection': 'SQL注入', 'xss': 'XSS攻击', 'webshell_upload': 'Webshell上传',
    'ssh_brute_force': 'SSH暴破', 'port_scan': '端口扫描', 'ddos': 'DDoS攻击',
    'ddos_suspected': 'DDoS疑似', 'directory_traversal': '目录遍历', 'directory_brute': '目录爆破',
    'cc_attack': 'CC攻击', 'data_exfiltration': '数据外泄', 'malicious_crawler': '恶意爬虫',
    'rate_limit_violation': '频率超限', 'ban_limit_reached': '封禁上限（仅告警）',
  }
  if (t.startsWith('rate_limited')) return '限速触发'
  if (t.startsWith('banned')) return '已封禁'
  return map[t] || t
}
const threatType = (level: string) => {
  const map: Record<string, string> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }
  return map[level] || 'info'
}
const threatLabel = (level: string) => {
  const map: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return map[level] || level
}
const actionType = (action: string) => {
  if (!action) return 'info'
  if (action === 'alert_only' || action.includes('skip') || action.includes('whitelist')) return 'info'
  if (action.startsWith('banned') || action.startsWith('ban_limit')) return 'danger'
  if (action.startsWith('rate_limit')) return 'warning'
  if (action.startsWith('ban_failed')) return 'danger'
  return 'info'
}
const actionLabel = (action: string) => {
  if (!action) return '仅告警'
  const map: Record<string, string> = {
    'alert_only': '仅告警',
    'skip_private_ip': '跳过（内网IP）',
    'whitelisted_skip': '跳过（白名单）',
    'rate_limited_5rps': '限速 5req/s',
    'banned_1h': '封禁 1小时',
    'banned_30m': '封禁 30分钟',
    'banned_24h': '封禁 24小时',
    'banned_7d': '封禁 7天',
    'ban_limit_reached': '封禁上限（仅告警）',
    'ban_limit_reached_alert_only': '封禁上限（仅告警）',
    'ban_limit_alert_only': '封禁上限（仅告警）',
  }
  if (action.startsWith('ban_failed')) return '封禁失败'
  if (action.startsWith('rate_limit_failed')) return '限速失败'
  if (action.startsWith('banned_')) {
    const dur = action.replace('banned_', '')
    return `封禁 ${dur}`
  }
  return map[action] || action
}

// 格式化详情：如果是 JSON 则解析为可读文本，否则直接返回
const formatDetail = (detail: string) => {
  if (!detail) return '-'
  // 检查是否是 JSON 格式（旧数据可能还是 JSON）
  if (detail.trim().startsWith('{')) {
    try {
      const obj = JSON.parse(detail)
      const parts: string[] = []
      // 常见字段中文映射
      const fieldMap: Record<string, string> = {
        'pattern': '匹配特征',
        'url': '攻击URL',
        'request_count': '请求次数',
        'fail_count': '失败次数',
        'port_count': '端口数量',
        'ports': '探测端口',
        'connection_count': '连接数',
        'product': '软件',
        'current_version': '当前版本',
        'cve': 'CVE编号',
        'severity': '严重程度',
        'cms': 'CMS',
        'version': '版本',
        'path': '路径',
        'file': '文件',
        'size': '大小',
        'config': '配置项',
        'value': '当前值',
        'param': '参数',
        'current': '当前值',
        'expected': '建议值',
      }
      for (const [key, value] of Object.entries(obj)) {
        const label = fieldMap[key] || key
        parts.push(`${label}: ${value}`)
      }
      return parts.join('，') || detail
    } catch {
      return detail
    }
  }
  return detail
}

const formatTime = (ts: string) => ts ? dayjs(ts).format('YYYY-MM-DD HH:mm:ss') : '-'

const lookupIP = async (ip: string) => {
  if (ipLocationCache.value[ip]) return
  ipLookupIP.value = ip
  try {
    const resp = await axios.get('/api/ip-location', { params: { ip } })
    const loc = resp.data.location || '未知'
    ipLocationCache.value = { ...ipLocationCache.value, [ip]: loc }
  } catch {
    ipLocationCache.value = { ...ipLocationCache.value, [ip]: '查询失败' }
  } finally {
    ipLookupIP.value = ''
  }
}

// 自动批量查询当前页所有 IP 的属地
const autoLookupIPs = async () => {
  const uniqueIPs = new Set<string>()
  for (const event of pagedEvents.value) {
    const ip = event.source_ip
    if (ip && !isPrivateIP(ip) && !ipLocationCache.value[ip]) {
      uniqueIPs.add(ip)
    }
  }
  // 并发查询（限制并发数）
  const ips = Array.from(uniqueIPs).slice(0, 10) // 每页最多查 10 个
  await Promise.all(ips.map(ip => lookupIP(ip)))
}

// 监听分页变化，自动查询新页的 IP
watch([currentPage, pageSize], () => {
  autoLookupIPs()
})

// 判断是否为持久攻击者画像（attack_profiles 表中 id 以 persistent: 开头）
const isPersistent = (row: any) => {
  return typeof row?.id === 'string' && row.id.startsWith('persistent:')
}

// 格式化攻击画像中的攻击类型列表为中文
const formatAttackTypes = (types: string) => {
  if (!types) return '-'
  return types.split(',').map((t: string) => attackTypeLabel(t.trim())).join('、')
}

const showAttackDetail = (row: any) => {
  currentAttack.value = row
  attackDetailVisible.value = true
}

const loadEvents = async () => {
  loadingEvents.value = true
  try {
    const resp = await axios.get('/api/attack-events', { params: { limit: 200 } })
    events.value = resp.data.events || []
    // 加载完成后自动查询当前页 IP 属地
    setTimeout(autoLookupIPs, 100)
  } catch {
    // 静默失败
  } finally {
    loadingEvents.value = false
  }
}

const loadProfiles = async () => {
  loadingProfiles.value = true
  try {
    const resp = await axios.get('/api/attack-profiles', { params: { limit: 100 } })
    profiles.value = resp.data.profiles || []
  } catch {
    // 静默失败
  } finally {
    loadingProfiles.value = false
  }
}

const loadBanned = async () => {
  loadingBanned.value = true
  try {
    const resp = await axios.get('/api/scan/attackwarn/banned')
    bannedIPs.value = resp.data.banned || []
  } catch {
    // 静默失败
  } finally {
    loadingBanned.value = false
  }
}

// 跳转到攻击预警页面并定位某个IP
const goToAttacks = (ip: string) => {
  router.push({ path: '/attacks', query: { ip } })
}

const triggerScan = async () => {
  scanning.value = true
  try {
    const resp = await axios.post('/api/scan/attackwarn', {})
    ElMessage.success(resp.data.message || '扫描完成')
    loadEvents()
    loadProfiles()
    loadBanned()
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.error || '扫描失败')
  } finally {
    scanning.value = false
  }
}

const emergencyRollback = async () => {
  try {
    await ElMessageBox.confirm(
      '确认回滚所有封禁规则？此操作将清除 ServerGuard 添加的所有 IP 封禁规则，不可逆。',
      '紧急回滚',
      { type: 'warning', confirmButtonText: '确认回滚', cancelButtonText: '取消' }
    )
    await axios.post('/api/attack-profiles/emergency-rollback', { reason: 'manual_rollback_from_ui' })
    ElMessage.success('已回滚所有封禁规则')
    loadBanned()
  } catch (e: any) {
    if (e !== 'cancel' && e?.message !== 'cancel') {
      ElMessage.error('回滚失败')
    }
  }
}

const loadAll = () => {
  loadEvents()
  loadProfiles()
  loadBanned()
}

onMounted(() => {
  loadAll()
  // 每 30 秒自动刷新，展示 Agent 自动扫描的最新结果
  refreshTimer = setInterval(loadAll, 60000)
})

onUnmounted(() => {
  if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null }
})
</script>

<style scoped>
.attack-page { width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; }
.header-actions { display: flex; gap: 10px; align-items: center; }
</style>
