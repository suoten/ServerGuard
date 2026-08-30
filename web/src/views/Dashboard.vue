<template>
  <div class="dashboard">
    <!-- ═══════════════════════════════════════════════════
         第 0 行：错误状态 / 宝塔提示
         ═══════════════════════════════════════════════════ -->
    <el-alert
      v-if="fetchError"
      type="error"
      :closable="false"
      show-icon
      style="margin-bottom: 16px"
    >
      <template #title>数据加载失败</template>
      <template #default>
        无法获取服务器数据，请检查 Agent 是否正常运行。
        <el-button text type="primary" size="small" @click="fetchData" style="margin-left: 8px">重试</el-button>
        <el-button text size="small" @click="$router.push('/settings')">联系支持</el-button>
      </template>
    </el-alert>

    <!-- ═══════════════════════════════════════════════════
         第 0.5 行：ServerGuard 作战日志（首屏视觉中心）
         "ServerGuard 在过去 24 小时为你做了什么"
         让用户一眼看到价值，不用翻页面
         ═══════════════════════════════════════════════════ -->
    <el-card shadow="hover" class="battle-log-card">
      <div class="battle-log-header">
        <span class="battle-log-title">
          <el-icon :color="autoActionSummary.total > 0 ? '#52c41a' : '#909399'"><Tools /></el-icon>
          ServerGuard 24 小时作战日志
        </span>
        <el-tag v-if="autoActionSummary.total > 0" size="small" type="success">{{ autoActionSummary.total }} 次自动操作</el-tag>
        <el-tag v-else size="small" type="info">一切正常</el-tag>
      </div>
      <div class="battle-log-body">
        <template v-if="autoActionSummary.total > 0">
          <div class="battle-log-items">
            <div v-if="autoActionSummary.banIP > 0" class="battle-log-item battle-log-ban">
              <el-icon color="#f56c6c"><Lock /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.banIP }}</div>
                <div class="bl-label">个攻击 IP 被封禁</div>
              </div>
            </div>
            <div v-if="autoActionSummary.cleanLog > 0" class="battle-log-item battle-log-clean">
              <el-icon color="#1890ff"><Document /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.cleanLog }}</div>
                <div class="bl-label">次日志自动清理</div>
              </div>
            </div>
            <div v-if="autoActionSummary.cleanDisk > 0" class="battle-log-item battle-log-disk">
              <el-icon color="#52c41a"><FolderOpened /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.cleanDisk }}</div>
                <div class="bl-label">次磁盘空间回收</div>
              </div>
            </div>
            <div v-if="autoActionSummary.renewCert > 0" class="battle-log-item battle-log-cert">
              <el-icon color="#52c41a"><Key /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.renewCert }}</div>
                <div class="bl-label">张证书自动续期</div>
              </div>
            </div>
            <div v-if="autoActionSummary.restart > 0" class="battle-log-item battle-log-restart">
              <el-icon color="#faad14"><RefreshRight /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.restart }}</div>
                <div class="bl-label">次服务自动重启</div>
              </div>
            </div>
            <div v-if="autoActionSummary.kill > 0" class="battle-log-item battle-log-kill">
              <el-icon color="#f56c6c"><CloseBold /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.kill }}</div>
                <div class="bl-label">个异常进程被终止</div>
              </div>
            </div>
            <div v-if="autoActionSummary.reloadNginx > 0" class="battle-log-item battle-log-nginx">
              <el-icon color="#1890ff"><Connection /></el-icon>
              <div class="bl-content">
                <div class="bl-number">{{ autoActionSummary.reloadNginx }}</div>
                <div class="bl-label">次 Nginx 自动重载</div>
              </div>
            </div>
          </div>
          <div class="battle-log-footer">
            <span v-if="autoActionSummary.successRate < 100" class="bl-rate">
              操作成功率 <strong :style="{ color: autoActionSummary.successRate >= 80 ? '#52c41a' : '#f56c6c' }">{{ autoActionSummary.successRate != null ? Number(autoActionSummary.successRate).toFixed(2) : '--' }}%</strong>
            </span>
            <span class="bl-link" @click="$router.push('/logs')">
              查看操作详情 <el-icon><ArrowRight /></el-icon>
            </span>
          </div>
        </template>
        <div v-else class="battle-log-empty">
          <el-icon :size="32" color="#52c41a"><CircleCheck /></el-icon>
          <span>过去 24 小时服务器一切正常，ServerGuard 持续守护中</span>
        </div>
      </div>
    </el-card>

    <!-- ═══════════════════════════════════════════════════
         第 1 行：健康评分
         ═══════════════════════════════════════════════════ -->
    <el-card class="health-card" shadow="hover" style="margin-top: 16px" @click="showDeductions = !showDeductions">
      <!-- 骨架屏：首次加载 -->
      <el-skeleton v-if="!healthScore && !fetchError" :rows="0" animated>
        <template #template>
          <div style="display: flex; align-items: center; gap: 40px; padding: 20px 0">
            <el-skeleton-item variant="circle" style="width: 140px; height: 140px" />
            <div style="flex: 1">
              <el-skeleton-item variant="h3" style="width: 60%; margin-bottom: 12px" />
              <el-skeleton-item variant="text" style="width: 40%" />
            </div>
          </div>
        </template>
      </el-skeleton>

      <!-- 正常状态 -->
      <div v-else-if="healthScore" class="health-content">
        <!-- 左侧：ECharts 环形评分 -->
        <div class="health-gauge">
          <v-chart
            :option="gaugeOption"
            :autoresize="true"
            style="width: 160px; height: 160px"
          />
        </div>

        <!-- 中间：分数 + 人话解释 -->
        <div class="health-summary">
          <div class="health-score-num" :style="{ color: scoreColor }">
            {{ healthScore.total != null ? Number(healthScore.total).toFixed(2) : '--' }}
            <span class="health-score-unit">分</span>
          </div>
          <div class="health-trend">
            <span v-if="healthScore.trend === 'up'" style="color: #67c23a">↑ 好转</span>
            <span v-else-if="healthScore.trend === 'down'" style="color: #f56c6c">↓ 恶化</span>
            <span v-else style="color: #909399">— 稳定</span>
          </div>
          <div class="health-explain">{{ healthExplanation }}</div>
        </div>

        <!-- 右侧：三个子维度迷你进度 -->
        <div class="health-sub-scores">
          <div class="sub-item">
            <span class="sub-label">性能</span>
            <el-progress
              :percentage="healthScore.performance"
              :color="subScoreColor(healthScore.performance)"
              :stroke-width="6"
              :show-text="false"
              style="flex: 1"
            />
            <span class="sub-val" :style="{ color: subScoreColor(healthScore.performance) }">{{ healthScore.performance != null ? Number(healthScore.performance).toFixed(2) : '--' }}</span>
          </div>
          <div class="sub-item">
            <span class="sub-label">可用性</span>
            <el-progress
              :percentage="healthScore.availability"
              :color="subScoreColor(healthScore.availability)"
              :stroke-width="6"
              :show-text="false"
              style="flex: 1"
            />
            <span class="sub-val" :style="{ color: subScoreColor(healthScore.availability) }">{{ healthScore.availability != null ? Number(healthScore.availability).toFixed(2) : '--' }}</span>
          </div>
          <div class="sub-item">
            <span class="sub-label">安全</span>
            <el-progress
              :percentage="healthScore.security"
              :color="subScoreColor(healthScore.security)"
              :stroke-width="6"
              :show-text="false"
              style="flex: 1"
            />
            <span class="sub-val" :style="{ color: subScoreColor(healthScore.security) }">{{ healthScore.security != null ? Number(healthScore.security).toFixed(2) : '--' }}</span>
          </div>
        </div>
      </div>

      <!-- 空状态：学习模式中 -->
      <div v-else-if="!fetchError" class="health-empty">
        <el-empty :image-size="60" description="">
          <template #image>
            <el-icon style="font-size: 48px; color: #c0c4cc"><Loading /></el-icon>
          </template>
          <div style="text-align: center">
            <p style="color: #606266; margin-bottom: 8px">当前为学习模式，系统只观察不操作</p>
            <p style="color: #909399; font-size: 13px; margin-bottom: 12px">ServerGuard 正在学习你的服务器正常状态，此期间不会执行任何自动修复。学习期默认 7 天，到期后自动开启自动修复。</p>
            <el-progress :percentage="learnProgress" :format="(p: number) => `${p}%`" style="width: 200px" />
          </div>
        </el-empty>
      </div>
    </el-card>

    <!-- 扣分明细展开（ElCollapse） -->
    <el-collapse-transition>
      <div v-if="showDeductions && healthScore?.deductions?.length" class="deductions-panel">
        <el-card shadow="never">
          <template #header>
            <span>扣分明细（点击可跳转修复）</span>
            <el-tag size="small" type="info" style="margin-left: 8px">共扣 {{ totalDeductions }} 分</el-tag>
          </template>
          <div
            v-for="(d, i) in healthScore.deductions"
            :key="i"
            class="deduction-row"
            @click="navigateToFix(d)"
          >
            <el-tag :type="deductionTagType(d.category)" size="small">{{ deductionCategoryLabel(d.category) }}</el-tag>
            <span class="deduction-reason">{{ d.reason }}</span>
            <span class="deduction-points">-{{ d.points }} 分</span>
            <el-icon class="deduction-arrow"><ArrowRight /></el-icon>
          </div>
        </el-card>
      </div>
    </el-collapse-transition>

    <!-- ═══════════════════════════════════════════════════
         第 1.5 行：智能洞察（基线状态/内存趋势/变慢站点）
         紧凑横条：正常时绿色收敛，异常时逐项标红/橙
         ═══════════════════════════════════════════════════ -->
    <el-card v-if="insights" shadow="hover" class="insights-card" style="margin-top: 16px">
      <div class="insights-row">
        <span class="insights-title">
          <el-icon><MagicStick /></el-icon>智能洞察
        </span>

        <!-- 学习模式 -->
        <span v-if="insightsLearning" class="insight-item insight-muted">
          学习模式中：正在积累基线数据，暂不做异常判断
        </span>

        <template v-else>
          <!-- 指标基线状态 -->
          <span
            v-for="m in insightMetrics"
            :key="m.name"
            class="insight-item"
            :class="m.anomaly ? 'insight-bad' : 'insight-ok'"
          >
            <template v-if="m.ready">
              {{ m.label }} {{ Number(m.current || 0).toFixed(0) }}{{ m.unit }} · 正常 {{ baselineRange(m) }}<template v-if="m.anomaly">（偏离 {{ Number(m.sigmas || 0).toFixed(1) }}σ）</template>
            </template>
            <template v-else>
              {{ m.label }} {{ Number(m.current || 0).toFixed(0) }}{{ m.unit }} · 基线学习中
            </template>
          </span>

          <!-- OOM 内存趋势风险 -->
          <span v-if="memTrend?.risk" class="insight-item insight-bad">
            内存增速 +{{ Number(memTrend.slope_per_min || 0).toFixed(1) }}%/min · 约 {{ Math.round(memTrend.minutes_left || 0) }} 分钟后耗尽
          </span>

          <!-- 变慢站点 -->
          <span v-for="s in slowSites" :key="s.id" class="insight-item insight-warn">
            站点「{{ s.name }}」变慢 · {{ Number(s.current_ms || 0).toFixed(0) }}ms（常态 {{ Number(s.mean_ms || 0).toFixed(0) }}ms）
          </span>

          <!-- 全部正常 -->
          <span v-if="insightsAllClear" class="insight-item insight-ok">
            ✓ 各项指标均在基线范围内
          </span>
        </template>
      </div>
    </el-card>

    <!-- ═══════════════════════════════════════════════════
         第 1.6 行：安全更新提醒（CVE Feed Monitor）
         有漏洞/补丁时显示，无则隐藏
         ═══════════════════════════════════════════════════ -->
    <el-card
      v-if="securityUpdates && hasSecurityUpdates"
      shadow="hover"
      class="security-updates-card"
      style="margin-top: 16px"
    >
      <div class="security-updates-row">
        <span class="security-updates-title">
          <el-icon :class="securityUpdatesIconClass"><Lock /></el-icon>
          安全更新提醒
          <el-tag size="small" :type="securityUpdatesTagType" style="margin-left: 4px">{{ securityUpdatesSummary }}</el-tag>
        </span>
        <div class="security-updates-body">
          <!-- 匹配的 CVE 列表 -->
          <div v-if="securityUpdates.matched_cves?.length" class="security-updates-section">
            <div class="security-updates-section-title">⚠️ 影响本机软件的已知漏洞</div>
            <div
              v-for="cve in securityUpdates.matched_cves.slice(0, 5)"
              :key="cve.cve_id"
              class="security-update-item"
            >
              <el-tag :type="cveTagType(cve.severity)" size="small">{{ updateSeverityLabel(cve.severity) }}</el-tag>
              <span class="cve-id">{{ cve.cve_id }}</span>
              <span class="cve-product">{{ cve.product }}</span>
              <span class="cve-desc">{{ truncateText(cve.description, 80) }}</span>
              <a v-if="cve.reference_url" :href="cve.reference_url" target="_blank" class="cve-link">详情</a>
            </div>
            <div v-if="securityUpdates.matched_cves.length > 5" class="more-items">
              还有 {{ securityUpdates.matched_cves.length - 5 }} 个漏洞...
            </div>
          </div>

          <!-- 待安装的安全补丁 -->
          <div v-if="securityUpdates.pending_updates?.length" class="security-updates-section">
            <div class="security-updates-section-title">📦 待安装的安全补丁</div>
            <div
              v-for="u in securityUpdates.pending_updates.slice(0, 5)"
              :key="u.package_name"
              class="security-update-item"
            >
              <el-tag :type="updateTagType(u.severity)" size="small">{{ updateSeverityLabel(u.severity) }}</el-tag>
              <span class="pkg-name">{{ u.package_name }}</span>
              <span class="pkg-version">→ {{ u.update_version }}</span>
              <span v-if="u.advisory_id" class="pkg-advisory">{{ u.advisory_id }}</span>
            </div>
            <div v-if="securityUpdates.pending_updates.length > 5" class="more-items">
              还有 {{ securityUpdates.pending_updates.length - 5 }} 个补丁...
            </div>
          </div>

          <!-- 修复建议 -->
          <div class="security-updates-actions">
            <el-button type="primary" size="small" @click="triggerSecurityCheck" :loading="securityUpdatesLoading">
              重新检查
            </el-button>
            <span class="security-updates-hint">建议在测试环境验证后执行升级操作</span>
          </div>
        </div>
      </div>
    </el-card>

    <!-- ═══════════════════════════════════════════════════
         第 2 行：资源迷你图表（CPU/内存/磁盘/网络）
         高度: ~120px（图表 80px + 卡片头 40px）
         ═══════════════════════════════════════════════════ -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :sm="12" :md="6">
        <el-card shadow="hover" class="mini-chart-card">
          <template #header>
            <div class="mini-chart-header">
              <span>cpu 使用率</span>
              <el-tag :type="cpuTagType" size="small">{{ cpuStatus }}</el-tag>
            </div>
          </template>
          <v-chart
            v-if="cpuHistory.length >= 2"
            :option="cpuChartOption"
            :autoresize="true"
            style="height: 80px"
          />
          <el-skeleton v-else :rows="0" animated style="padding: 20px 0">
            <template #template>
              <el-skeleton-item variant="text" style="width: 100%; height: 60px" />
            </template>
          </el-skeleton>
          <div class="mini-chart-footer">
            {{ cpuPercent }}% · {{ cpuCores }} 核 · 负载 {{ loadAvg }}
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card shadow="hover" class="mini-chart-card">
          <template #header>
            <div class="mini-chart-header">
              <span>内存使用率</span>
              <el-tag :type="memTagType" size="small">{{ memStatus }}</el-tag>
            </div>
          </template>
          <v-chart
            v-if="memHistory.length >= 2"
            :option="memChartOption"
            :autoresize="true"
            style="height: 80px"
          />
          <el-skeleton v-else :rows="0" animated style="padding: 20px 0">
            <template #template>
              <el-skeleton-item variant="text" style="width: 100%; height: 60px" />
            </template>
          </el-skeleton>
          <div class="mini-chart-footer">
            {{ memPercent }}% · {{ memUsed }} / {{ memTotal }}
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card shadow="hover" class="mini-chart-card">
          <template #header>
            <div class="mini-chart-header">
              <span>磁盘使用率</span>
              <el-tag :type="diskTagType" size="small">{{ diskStatus }}</el-tag>
            </div>
          </template>
          <v-chart
            v-if="diskHistory.length >= 2"
            :option="diskChartOption"
            :autoresize="true"
            style="height: 80px"
          />
          <el-skeleton v-else :rows="0" animated style="padding: 20px 0">
            <template #template>
              <el-skeleton-item variant="text" style="width: 100%; height: 60px" />
            </template>
          </el-skeleton>
          <div class="mini-chart-footer">
            <el-tooltip v-if="(metrics?.disks || []).length > 1" :show-after="200" placement="top" effect="dark">
              <template #content>
                <div v-for="d in (metrics?.disks || [])" :key="d.mount_point" style="line-height: 1.8">
                  {{ d.mount_point }}：{{ Math.round(d.used_percent) }}% · {{ formatBytes(d.used) }} / {{ formatBytes(d.total) }}
                </div>
              </template>
              <span style="cursor: help; border-bottom: 1px dashed #c0c4cc">
                {{ diskPercent }}% · {{ diskPath || '无磁盘数据' }} · {{ formatBytes(diskUsed) }} / {{ formatBytes(diskTotal) }}
              </span>
            </el-tooltip>
            <span v-else>{{ diskPercent }}% · {{ diskPath || '无磁盘数据' }} · {{ formatBytes(diskUsed) }} / {{ formatBytes(diskTotal) }}</span>
            <template v-if="diskForecastDays > 0"> · <span :style="{ color: diskForecastDays <= 7 ? '#f56c6c' : '#e6a23c' }">预计 {{ diskForecastDays }} 天后写满</span></template>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :sm="12" :md="6">
        <el-card shadow="hover" class="mini-chart-card">
          <template #header>
            <div class="mini-chart-header">
              <span>网络流量</span>
              <el-tag type="success" size="small">{{ netStatus }}</el-tag>
            </div>
          </template>
          <v-chart
            v-if="netHistory.length >= 2"
            :option="netChartOption"
            :autoresize="true"
            style="height: 80px"
          />
          <el-skeleton v-else :rows="0" animated style="padding: 20px 0">
            <template #template>
              <el-skeleton-item variant="text" style="width: 100%; height: 60px" />
            </template>
          </el-skeleton>
          <div class="mini-chart-footer">
            ↑{{ netSentText }} · ↓{{ netRecvText }} <span style="font-size:11px;color:#c0c4cc">/15s</span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- ═══════════════════════════════════════════════════
         第 3 行：守护状态卡片 + 事件流
         左侧守护卡片 (md=16) / 右侧事件流 (md=8)
         ═══════════════════════════════════════════════════ -->
    <el-row :gutter="16" style="margin-top: 16px; align-items: stretch">
      <!-- 守护状态卡片 -->
      <el-col :xs="24" :md="16" style="display: flex; flex-direction: column">
        <el-card shadow="hover" style="flex: 1">
          <template #header>
            <div class="card-header">
              <span>守护状态</span>
              <el-button text size="small" @click="$router.push('/guards')">管理守护</el-button>
            </div>
          </template>

          <!-- 守护卡片网格 -->
          <el-row :gutter="12">
            <el-col
              v-for="g in guardList"
              :key="g.id"
              :xs="24"
              :sm="12"
              :md="8"
              style="margin-bottom: 12px"
            >
              <el-card
                shadow="never"
                :class="['guard-card', { 'guard-abnormal': guardStatus(g) === 'abnormal' }]"
                :body-style="{ padding: '12px' }"
              >
                <div class="guard-card-header">
                  <span class="guard-name">{{ g.name }}</span>
                  <el-tag :type="guardTagType(guardStatus(g))" size="small" effect="light">
                    {{ guardStatusLabel(guardStatus(g)) }}
                  </el-tag>
                </div>
                <div class="guard-card-desc">{{ guardDescription(g) }}</div>

                <!-- 展开最近 3 条事件 -->
                <el-collapse-transition>
                  <div v-if="expandedGuard === g.id" class="guard-events">
                    <div
                      v-for="(evt, idx) in guardRecentEvents(g)"
                      :key="idx"
                      class="guard-event-item"
                    >
                      <el-icon :style="{ color: eventIconColor(evt), fontSize: '14px' }">
                        <component :is="eventIconComponent(evt)" />
                      </el-icon>
                      <span class="guard-event-text">{{ eventShortText(evt) }}</span>
                      <span class="guard-event-time">{{ formatRelativeTime(evt.timestamp) }}</span>
                    </div>
                    <p v-if="guardRecentEvents(g).length === 0" class="guard-no-events">
                      暂无近期事件
                    </p>
                  </div>
                </el-collapse-transition>

                <el-button
                  text
                  size="small"
                  @click.stop="toggleGuardExpand(g.id)"
                  style="margin-top: 4px; padding: 0"
                >
                  {{ expandedGuard === g.id ? '收起' : '查看最近事件' }}
                </el-button>
              </el-card>
            </el-col>
          </el-row>

          <!-- 空状态 -->
          <el-empty
            v-if="guardList.length === 0 && !loading"
            :image-size="60"
            description="还没有添加守护目标"
          >
            <el-button type="primary" size="small" @click="$router.push('/guards')">添加守护</el-button>
          </el-empty>
        </el-card>
      </el-col>

<!-- 事件流 -->
      <el-col :xs="24" :md="8" style="display: flex; flex-direction: column">
        <el-card shadow="hover" class="event-card" style="flex: 1">
          <template #header>
            <div class="card-header">
              <span>最近事件</span>
              <el-button-group v-if="recentEvents.length > 0">
                <el-button size="small" @click="ackAllEvents">确认全部</el-button>
                <el-button size="small" @click="markAllRead">标记已读</el-button>
              </el-button-group>
            </div>
          </template>

          <!-- 事件列表 -->
          <div v-if="recentEvents.length > 0" class="event-list">
            <div
              v-for="evt in recentEvents"
              :key="evt.id || evt.timestamp"
              class="event-item"
              :class="{ 'event-unread': !evt.acknowledged, 'event-clickable': !!eventLink(evt) }"
              @click="onEventClick(evt)"
            >
              <el-icon :style="{ color: eventIconColor(evt), fontSize: '18px' }">
                <component :is="eventIconComponent(evt)" />
              </el-icon>
              <div class="event-body">
                <div class="event-title-row">
                  <span class="event-text">{{ evt.title || evt.message || '' }}</span>
                  <el-tag v-if="evt.processed" type="success" size="small" effect="plain">已处理</el-tag>
                  <el-tag v-else-if="evt.source === 'agent'" type="primary" size="small" effect="plain">自动修复</el-tag>
                  <el-tag v-else-if="evt.level === 'critical' || evt.level === 'error' || evt.level === 'fatal'" type="danger" size="small" effect="plain">待处理</el-tag>
                </div>
                <!-- 完整消息内容（如果和标题不同） -->
                <div v-if="evt.message && evt.message !== evt.title" class="event-message">{{ evt.message }}</div>
                <div class="event-time-row">
                  <span class="event-time">{{ formatTime(evt.timestamp) }}</span>
                  <el-link v-if="eventLink(evt)" type="primary" underline="never" size="small" class="event-link" @click.stop="onEventClick(evt)">
                    {{ eventLinkLabel(evt) }}
                    <el-icon style="font-size: 12px"><ArrowRight /></el-icon>
                  </el-link>
                </div>
              </div>
            </div>
          </div>

          <!-- 空状态 -->
          <el-empty
            v-else-if="!loading"
            :image-size="40"
            description="暂无事件，系统运行正常"
          />
        </el-card>
      </el-col>
    </el-row>

    <!-- ═══════════════════════════════════════════════════
         第 4 行：TOP 进程（CPU + 内存）
         ═══════════════════════════════════════════════════ -->
    <el-row :gutter="16" style="margin-top: 16px">
      <el-col :xs="24" :md="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>CPU 占用 TOP 10</span>
              <el-button text size="small" @click="fetchTopProcesses">刷新</el-button>
            </div>
          </template>
          <el-table :data="topCPUProcesses" size="small" stripe v-loading="loadingTopProc">
            <el-table-column label="#" width="40" type="index" />
            <el-table-column label="进程" min-width="180">
              <template #default="{ row }">
                <div style="line-height: 1.4">
                  <div style="font-weight: 600; font-size: 13px">{{ row.cmdline || row.name }}</div>
                  <div v-if="row.cmdline && row.cmdline !== row.name" style="font-size: 11px; color: #909399">{{ row.name }} (PID: {{ row.pid }})</div>
                  <div v-else style="font-size: 11px; color: #909399">PID: {{ row.pid }}</div>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="CPU%" width="80" align="right">
              <template #default="{ row }">
                <span :style="{ color: row.cpu_percent > 50 ? '#f56c6c' : row.cpu_percent > 20 ? '#e6a23c' : '#67c23a', fontWeight: 600 }">{{ Number(row.cpu_percent || 0).toFixed(1) }}%</span>
              </template>
            </el-table-column>
            <el-table-column label="内存" width="80" align="right">
              <template #default="{ row }">{{ Number(row.mem_mb || 0).toFixed(0) }}MB</template>
            </el-table-column>
          </el-table>
          <template #empty>
            <p style="color: #909399; padding: 16px 0; font-size: 13px">暂无进程数据</p>
          </template>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card shadow="hover">
          <template #header>
            <div class="card-header">
              <span>内存占用 TOP 10</span>
            </div>
          </template>
          <el-table :data="topMemProcesses" size="small" stripe v-loading="loadingTopProc">
            <el-table-column label="#" width="40" type="index" />
            <el-table-column label="进程" min-width="180">
              <template #default="{ row }">
                <div style="line-height: 1.4">
                  <div style="font-weight: 600; font-size: 13px">{{ row.cmdline || row.name }}</div>
                  <div v-if="row.cmdline && row.cmdline !== row.name" style="font-size: 11px; color: #909399">{{ row.name }} (PID: {{ row.pid }})</div>
                  <div v-else style="font-size: 11px; color: #909399">PID: {{ row.pid }}</div>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="内存%" width="80" align="right">
              <template #default="{ row }">
                <span :style="{ color: row.mem_percent > 30 ? '#f56c6c' : row.mem_percent > 10 ? '#e6a23c' : '#67c23a', fontWeight: 600 }">{{ Number(row.mem_percent || 0).toFixed(1) }}%</span>
              </template>
            </el-table-column>
            <el-table-column label="RSS" width="80" align="right">
              <template #default="{ row }">{{ Number(row.mem_mb || 0).toFixed(0) }}MB</template>
            </el-table-column>
          </el-table>
          <template #empty>
            <p style="color: #909399; padding: 16px 0; font-size: 13px">暂无进程数据</p>
          </template>
        </el-card>
      </el-col>
    </el-row>

    <!-- ═══════════════════════════════════════════════════
         第 5 行：网站存活 + 系统状态摘要（可选）
         ═══════════════════════════════════════════════════ -->
    <el-row v-if="sites.length > 0" :gutter="16" style="margin-top: 16px">
      <el-col :span="24">
        <el-card shadow="hover">
          <template #header><span>网站存活性监控</span></template>
          <div class="sites-list">
            <div v-for="s in sites" :key="s.id" class="site-item">
              <span class="site-light" :class="siteLightClass(s)"></span>
              <span class="site-name">{{ s.name }}</span>
              <el-tag :type="s.up ? 'success' : 'danger'" size="small">
                {{ s.up ? '正常' : '不可用' }}
              </el-tag>
              <span v-if="s.up" class="site-latency">{{ Number((s.latency || 0) / 1000000).toFixed(0) }}ms</span>
              <span v-else class="site-latency error">{{ s.last_error || '连接失败' }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'
import dayjs from 'dayjs'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GaugeChart, LineChart } from 'echarts/charts'
import {
  TooltipComponent,
  GridComponent,
  TitleComponent,
} from 'echarts/components'
import {
  Loading,
  Warning,
  CircleCheck,
  InfoFilled,
  Tools,
  ArrowRight,
  MagicStick,
  Lock,
  Document,
  RefreshRight,
  CloseBold,
  FolderOpened,
  Key,
  Connection,
  // Shield not available in this version, using Tools instead
} from '@element-plus/icons-vue'
import { useDark } from '@/composables/useDark'

use([CanvasRenderer, GaugeChart, LineChart, TooltipComponent, GridComponent, TitleComponent])

const { isDark } = useDark()

const router = useRouter()

// ═══════════════════════════════════════════════════
// 响应式数据
// ═══════════════════════════════════════════════════
const metrics = ref<any>({})
const alerts = ref<any[]>([])
const safety = ref<any>({})
const guards = ref<any[]>([])
const sites = ref<any[]>([])
const healthScore = ref<any>(null)
const insights = ref<any>(null)

// 安全更新提醒（CVE Feed Monitor）
const securityUpdates = ref<any>(null)
const securityUpdatesLoading = ref(false)
const loading = ref(true)
const fetchError = ref(false)
const showDeductions = ref(false)
const expandedGuard = ref<string | null>(null)
const learnProgress = ref(0)

// TOP 进程数据
const topCPUProcesses = ref<any[]>([])
const topMemProcesses = ref<any[]>([])
const loadingTopProc = ref(false)

// 时序数据：客户端采集（每 5 秒一个点，保留 30 个点 = 2.5 分钟）
const MAX_HISTORY = 30
const cpuHistory = ref<{ time: string; value: number; baseline: number }[]>([])
const memHistory = ref<{ time: string; value: number; baseline: number }[]>([])
const diskHistory = ref<{ time: string; value: number; baseline: number }[]>([])
const netHistory = ref<{ time: string; sent: number; recv: number; baseline: number }[]>([])

// 上次网络 IO 采样值（累计字节），用于计算增量速率
let prevNetSent = 0
let prevNetRecv = 0

let timer: ReturnType<typeof setInterval> | null = null
let topProcTimer: ReturnType<typeof setInterval> | null = null

// ═══════════════════════════════════════════════════
// 计算属性：资源指标
// ═══════════════════════════════════════════════════
const cpuPercent = computed(() => Math.round(metrics.value?.cpu_percent || 0))
const cpuCores = computed(() => metrics.value?.cpu_cores || 0)
const loadAvg = computed(() => (metrics.value?.load_avg_1 || 0).toFixed(2))
const memPercent = computed(() => Math.round(metrics.value?.mem_percent || 0))
const memUsed = computed(() => ((metrics.value?.mem_used || 0) / 1024 / 1024 / 1024).toFixed(1) + ' GB')
const memTotal = computed(() => ((metrics.value?.mem_total || 0) / 1024 / 1024 / 1024).toFixed(1) + ' GB')
const diskPercent = computed(() => {
  const disks = metrics.value?.disks || []
  if (disks.length === 0) return 0
  // 取所有分区中最大的使用率
  return Math.round(Math.max(...disks.map((d: any) => d.used_percent || 0)))
})
const diskPath = computed(() => {
  const disks = metrics.value?.disks || []
  if (disks.length === 0) return ''
  // 取使用率最高的分区
  const sorted = [...disks].sort((a: any, b: any) => (b.used_percent || 0) - (a.used_percent || 0))
  const top = sorted[0]
  if (disks.length === 1) return top.mount_point
  return `${top.mount_point} 等 ${disks.length} 个分区`
})
// 磁盘已用量和总量：跟随显示使用率最高的那个分区
const diskTop = computed(() => {
  const disks = metrics.value?.disks || []
  if (disks.length === 0) return null
  const sorted = [...disks].sort((a: any, b: any) => (b.used_percent || 0) - (a.used_percent || 0))
  return sorted[0]
})
const diskUsed = computed(() => diskTop.value?.used || 0)
const diskTotal = computed(() => diskTop.value?.total || 0)
// 磁盘写满预测：优先匹配当前挂载点，其次取最紧急的一项
const diskForecastDays = computed(() => {
  const forecasts: any[] = metrics.value?.disk_forecast || []
  const matched = forecasts.find((f) => f.mount === diskPath.value && f.days_left > 0)
    || forecasts.find((f) => f.days_left > 0)
  return matched ? matched.days_left : -1
})

// ═══════════════════════════════════════════════════
// 计算属性：智能洞察（基线状态/内存趋势/变慢站点）
// ═══════════════════════════════════════════════════
const insightMetrics = computed(() => insights.value?.metrics || [])
const memTrend = computed(() => insights.value?.mem_trend || null)
const slowSites = computed(() => insights.value?.slow_sites || [])
const insightsLearning = computed(() => insights.value?.learning === true)

// 基线正常范围文本：mean±2σ
function baselineRange(m: any): string {
  if (!m.ready) return ''
  const mean = Number(m.mean || 0)
  const stddev = Number(m.stddev || 0)
  const lo = Math.max(0, mean - 2 * stddev)
  const hi = Math.min(100, mean + 2 * stddev)
  return `${lo.toFixed(0)}~${hi.toFixed(0)}${m.unit}`
}

// 全部正常判定（基线无偏离 + 内存无风险 + 无变慢站点 + 磁盘无紧急预测）
const insightsAllClear = computed(() => {
  if (!insights.value) return false
  const metricBad = insightMetrics.value.some((m: any) => m.anomaly)
  const trendBad = memTrend.value?.risk === true
  const sitesBad = slowSites.value.length > 0
  const diskBad = diskForecastDays.value > 0 && diskForecastDays.value <= 7
  return !metricBad && !trendBad && !sitesBad && !diskBad
})
// 网络流量：本周期增量（两次采样之间的差值），显示为速率而非开机累计值
const netSent = computed(() => {
  const cur = metrics.value?.net_bytes_sent || 0
  const delta = prevNetSent > 0 ? Math.max(0, cur - prevNetSent) : 0
  return delta
})
const netRecv = computed(() => {
  const cur = metrics.value?.net_bytes_recv || 0
  const delta = prevNetRecv > 0 ? Math.max(0, cur - prevNetRecv) : 0
  return delta
})
const netSentText = computed(() => formatBytes(netSent.value))
const netRecvText = computed(() => formatBytes(netRecv.value))

const cpuStatus = computed(() => cpuPercent.value > 80 ? '危险' : cpuPercent.value > 60 ? '繁忙' : '正常')
const cpuTagType = computed(() => cpuPercent.value > 80 ? 'danger' : cpuPercent.value > 60 ? 'warning' : 'success')
const memStatus = computed(() => memPercent.value > 80 ? '危险' : memPercent.value > 60 ? '繁忙' : '正常')
const memTagType = computed(() => memPercent.value > 80 ? 'danger' : memPercent.value > 60 ? 'warning' : 'success')
const diskStatus = computed(() => diskPercent.value > 90 ? '危险' : diskPercent.value > 70 ? '繁忙' : '正常')
const diskTagType = computed(() => diskPercent.value > 90 ? 'danger' : diskPercent.value > 70 ? 'warning' : 'success')
const netStatus = computed(() => '正常')

// ═══════════════════════════════════════════════════
// 计算属性：健康评分
// ═══════════════════════════════════════════════════
const scoreColor = computed(() => {
  const s = healthScore.value?.total ?? 100
  if (s >= 90) return '#52c41a'
  if (s >= 70) return '#faad14'
  return '#ff4d4f'
})

const scorePulse = computed(() => (healthScore.value?.total ?? 100) < 50)

const totalDeductions = computed(() => {
  return (healthScore.value?.deductions || []).reduce((sum: number, d: any) => sum + d.points, 0)
})

// 人话解释：根据扣分项自动生成
const healthExplanation = computed(() => {
  if (!healthScore.value) return ''
  const deductions = healthScore.value.deductions || []
  if (deductions.length === 0) return `${healthScore.value.total} 分：一切正常，服务器运行良好`

  const top3 = deductions.slice(0, 3).map((d: any) => `${d.reason}扣了 ${d.points} 分`)
  if (deductions.length > 3) {
    return `${healthScore.value.total} 分：${top3.join('，')}等`
  }
  return `${healthScore.value.total} 分：${top3.join('，')}`
})

// ═══════════════════════════════════════════════════
// 计算属性：守护状态
// ═══════════════════════════════════════════════════
const guardList = computed(() => guards.value.slice(0, 9))

// ═══════════════════════════════════════════════════
// 计算属性：24h 自动处理摘要
// 从 safety.recent_actions 聚合统计，让用户看到 ServerGuard 自动做了什么
// ═══════════════════════════════════════════════════
const autoActionSummary = computed(() => {
  const actions = safety.value?.recent_actions || []
  const summary = {
    total: actions.length,
    cleanLog: 0,
    restart: 0,
    kill: 0,
    banIP: 0,
    cleanDisk: 0,
    renewCert: 0,
    reloadNginx: 0,
    successCount: 0,
    successRate: 100,
  }
  for (const a of actions) {
    const type = a.action?.type || a.action_type || ''
    switch (type) {
      case 'clean_log': case 'rotate_log': summary.cleanLog++; break
      case 'restart': summary.restart++; break
      case 'kill': case 'sigterm': case 'sigkill': summary.kill++; break
      case 'ban_ip': summary.banIP++; break
      case 'clean_disk': summary.cleanDisk++; break
      case 'renew_cert': summary.renewCert++; break
      case 'reload_nginx': summary.reloadNginx++; break
    }
    if (a.success) summary.successCount++
  }
  summary.successRate = summary.total > 0 ? Math.round((summary.successCount / summary.total) * 100) : 100
  return summary
})

function guardStatus(g: any): string {
  if (!g.enabled) return 'paused'
  // 如果有近期失败告警，标记异常
  const relatedAlerts = alerts.value.filter(
    (a: any) => a.source === 'service' && a.title?.toLowerCase().includes((g.name || '').toLowerCase())
  )
  if (relatedAlerts.some((a: any) => a.level === 'critical' || a.level === 'error')) return 'abnormal'
  return 'running'
}

function guardStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    running: '正常运行',
    stopped: '已停止',
    restarting: '正在重启',
    abnormal: '异常',
    paused: '已暂停',
  }
  return labels[status] || '正常运行'
}

function guardTagType(status: string): string {
  const types: Record<string, string> = {
    running: 'success',
    stopped: 'danger',
    restarting: 'warning',
    abnormal: 'danger',
    paused: 'info',
  }
  return types[status] || 'success'
}

function guardDescription(g: any): string {
  const status = guardStatus(g)
  if (status === 'running') return `端口 ${g.port || '—'} 正常响应`
  if (status === 'abnormal') return '检测到异常，请查看事件'
  if (status === 'paused') return '已暂停监控'
  return '等待状态更新'
}

function guardRecentEvents(g: any): any[] {
  return alerts.value
    .filter((a: any) => a.source === 'service' && a.title?.toLowerCase().includes((g.name || '').toLowerCase()))
    .slice(0, 3)
}

function toggleGuardExpand(id: string) {
  expandedGuard.value = expandedGuard.value === id ? null : id
}

// ═══════════════════════════════════════════════════
// 事件流
// ═══════════════════════════════════════════════════
const recentEvents = computed(() => {
  const alertEvents = alerts.value.slice(0, 8).map((a: any) => ({
    ...a,
    processed: a.acknowledged || false,
    acknowledged: a.acknowledged || false,
  }))
  const actionEvents = (safety.value?.recent_actions || []).slice(0, 4).map((a: any) => ({
    id: a.id || a.timestamp,
    level: a.success ? 'info' : 'error',
    title: '🔁 ' + actionLabel(a.action?.type) + ' ' + (a.action?.params?.name || a.target || ''),
    source: 'agent',
    timestamp: a.timestamp,
    processed: a.success,
    acknowledged: true,
  }))
  // 合并 + 按时间倒序
  const all = [...alertEvents, ...actionEvents]
  all.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  return all.slice(0, 10)
})

function eventIconComponent(evt: any) {
  const source = evt.source || ''
  const level = evt.level || ''
  // 智能分析来源（基线检测/磁盘预测/守护智能）用魔法棒图标，颜色仍按严重度区分
  if (source === 'baseline' || source === 'forecast' || source === 'guardian') return MagicStick
  if (source === 'agent' || source === 'service') return Tools
  if (level === 'critical' || level === 'error' || level === 'fatal') return Warning
  if (level === 'warning') return Warning
  if (level === 'info') return InfoFilled
  return CircleCheck
}

function eventIconColor(evt: any): string {
  const level = evt.level || ''
  if (level === 'critical' || level === 'error' || level === 'fatal') return '#ff4d4f'
  if (level === 'warning') return '#faad14'
  if (evt.processed) return '#52c41a'
  return '#909399'
}

function eventShortText(evt: any): string {
  let text = evt.title || evt.message || ''
  // 限制 20 个中文字符
  if (text.length > 20) text = text.slice(0, 20) + '…'
  return text
}

// 根据 event source 返回跳转路径
function eventLink(evt: any): string {
  const source = evt.source || ''
  if (source === 'attackwarn') return '/attacks'
  if (source === 'serversecurity' || source === 'vulnscan' || source === 'websecurity') return '/findings'
  if (source === 'cert') return '/certs'
  if (source === 'correlation') return '/incidents'
  if (source === 'forecast') return '/dashboard'
  if (source === 'upgrade') return '/settings'
  if (source === 'storage') return '/dashboard'
  if (source === 'netquality') return '/monitoring'
  if (source === 'baota') return '/baota'
  return ''
}

// 跳转链接文案
function eventLinkLabel(evt: any): string {
  const source = evt.source || ''
  if (source === 'attackwarn') return '查看攻击详情'
  if (source === 'serversecurity' || source === 'vulnscan' || source === 'websecurity') return '查看安全发现'
  if (source === 'cert') return '查看证书'
  if (source === 'correlation') return '查看故障事件'
  if (source === 'upgrade') return '去升级'
  return '查看详情'
}

// 点击事件项跳转
function onEventClick(evt: any) {
  const link = eventLink(evt)
  if (link) {
    router.push(link)
  }
}

async function ackAllEvents() {
  const unresolved = alerts.value.filter((a: any) => !a.acknowledged)
  for (const a of unresolved) {
    try {
      await axios.post(`/api/alerts/${a.id}/ack`)
    } catch { /* 静默失败 */ }
  }
  await fetchData()
}

async function markAllRead() {
  alerts.value = alerts.value.map((a: any) => ({ ...a, acknowledged: true }))
}

// ═══════════════════════════════════════════════════
// ECharts 配置：健康评分环形图
// ═══════════════════════════════════════════════════
const gaugeOption = computed(() => {
  const score = healthScore.value?.total ?? 100
  const color = score >= 90 ? '#52c41a' : score >= 70 ? '#faad14' : '#ff4d4f'
  const trackColor = isDark.value ? '#263152' : '#f0f0f0'
  return {
    series: [
      {
        type: 'gauge',
        startAngle: 220,
        endAngle: -40,
        min: 0,
        max: 100,
        splitNumber: 0,
        progress: {
          show: true,
          width: 14,
          roundCap: true,
          itemStyle: { color },
        },
        axisLine: {
          lineStyle: { width: 14, color: [[1, trackColor]] },
        },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        detail: {
          show: false,
        },
        data: [{ value: score }],
      },
    ],
  }
})

// ═══════════════════════════════════════════════════
// ECharts 配置：资源迷你折线图
// ═══════════════════════════════════════════════════
function buildMiniLineOption(
  history: { time: string; value: number; baseline: number }[],
  color: string,
  unit: string,
  label: string,
) {
  if (history.length < 2) return {}
  const times = history.map((h) => h.time)
  const values = history.map((h) => h.value)
  const baselines = history.map((h) => h.baseline)
  const lastVal = Number(values[values.length - 1] || 0)
  const baseline = Number(baselines[baselines.length - 1] || 0)
  const diff = lastVal - baseline
  const diffText = diff > 5 ? `比正常时段高 ${diff.toFixed(0)}${unit}` : diff < -5 ? `比正常时段低 ${Math.abs(diff).toFixed(0)}${unit}` : '处于正常范围'

  return {
    grid: { top: 5, right: 5, bottom: 5, left: 5 },
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const p = params[0]
        if (!p) return ''
        const time = p.axisValueLabel || ''
        const val = typeof p.value === 'number' ? p.value.toFixed(2) : (p.value || '--')
        return `${time}<br/>${label} ${val}${unit}<br/>${diffText}`
      },
      confine: true,
      textStyle: { fontSize: 12 },
    },
    xAxis: {
      type: 'category',
      data: times,
      show: false,
    },
    yAxis: {
      type: 'value',
      show: false,
      min: 0,
      max: 100,
    },
    series: [
      {
        type: 'line',
        data: values,
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: color + '40' },
              { offset: 1, color: color + '05' },
            ],
          },
        },
      },
      {
        type: 'line',
        data: baselines,
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 1, color: isDark.value ? '#4a5878' : '#c0c4cc', type: 'dashed' },
      },
    ],
  }
}

const cpuChartOption = computed(() =>
  buildMiniLineOption(cpuHistory.value, '#52c41a', '%', 'cpu'),
)
const memChartOption = computed(() =>
  buildMiniLineOption(memHistory.value, '#1890ff', '%', '内存'),
)
const diskChartOption = computed(() =>
  buildMiniLineOption(diskHistory.value, '#faad14', '%', '磁盘'),
)

const netChartOption = computed(() => {
  if (netHistory.value.length < 2) return {}
  const times = netHistory.value.map((h) => h.time)
  const sent = netHistory.value.map((h) => h.sent)
  const recv = netHistory.value.map((h) => h.recv)

  return {
    grid: { top: 5, right: 5, bottom: 5, left: 5 },
    tooltip: {
      trigger: 'axis',
      formatter: (params: any) => {
        const time = params[0]?.axisValueLabel || ''
        const sVal = (params[0]?.value || 0) * 1024  // KB → bytes for formatBytes
        const rVal = (params[1]?.value || 0) * 1024
        return `${time}<br/>↑ 发送 ${formatBytes(sVal)}<br/>↓ 接收 ${formatBytes(rVal)}`
      },
      confine: true,
      textStyle: { fontSize: 12 },
    },
    xAxis: { type: 'category', data: times, show: false },
    yAxis: { type: 'value', show: false },
    series: [
      {
        type: 'line',
        name: '发送',
        data: sent,
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: '#52c41a' },
        areaStyle: { opacity: 0.1 },
      },
      {
        type: 'line',
        name: '接收',
        data: recv,
        smooth: true,
        symbol: 'none',
        lineStyle: { width: 2, color: '#1890ff' },
        areaStyle: { opacity: 0.1 },
      },
    ],
  }
})

// ═══════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════
function subScoreColor(p: number): string {
  if (p >= 90) return '#52c41a'
  if (p >= 70) return '#faad14'
  return '#ff4d4f'
}

function siteLightClass(s: any) {
  if (s.total_checks === 0) return 'gray'
  return s.up ? 'green' : 'red'
}

function deductionTagType(cat: string): string {
  if (cat === 'performance') return 'warning'
  if (cat === 'availability') return 'danger'
  return 'info'
}

function deductionCategoryLabel(cat: string): string {
  const labels: Record<string, string> = { performance: '性能', availability: '可用性', security: '安全' }
  return labels[cat] || cat
}

function navigateToFix(d: any) {
  if (d.category === 'security') router.push('/findings')
  else if (d.category === 'availability') router.push('/alerts')
  else router.push('/dashboard')
}

function actionLabel(type: string | undefined): string {
  const labels: Record<string, string> = {
    kill: '关闭进程', sigterm: '关闭进程', sigkill: '强制关闭',
    nice: '调整优先级', restart: '重启服务', clean_log: '清理日志',
    rotate_log: '日志轮转', ban_ip: '封禁IP', unban_ip: '解封IP',
    renew_cert: '续期证书', cert_renew: '证书续期', cert_scan: '证书扫描',
    reload_nginx: '重载Nginx', clean_disk: '清理磁盘', run_script: '执行脚本',
    alert: '发送告警', snapshot: '创建快照',
    cve_alert: 'CVE漏洞告警', cve_feed_check: 'CVE漏洞检测',
    security_update: '安全补丁告警', security_update_check: '安全补丁检测',
    ghost_scan: '幽灵文件扫描',
    emergency_stop: '紧急停止', emergency_resume: '恢复运行', emergency_rollback: '紧急回滚',
    fix_finding: '修复安全发现', auto_fix_finding: '自动修复',
    confirm_finding: '确认安全发现', mark_false_positive: '标记误报',
    resolve_alert: '解决告警',
    delete_large_file: '删除大文件', batch_delete_large_file: '批量删除大文件',
    config_change: '修改配置', save_settings: '保存设置',
    add_rule: '添加规则', update_rule: '更新规则', toggle_rule: '切换规则', delete_rule: '删除规则',
    add_guard: '添加守护', remove_guard: '移除守护',
    add_probe_site: '添加监控站点', delete_probe_site: '删除监控站点',
    scan_websecurity: '网站安全扫描', scan_vulnscan: '漏洞扫描',
    scan_serversecurity: '服务器安全扫描', scan_attackwarn: '攻击预警扫描',
    create_maintenance_window: '创建维护窗口', delete_maintenance_window: '删除维护窗口',
    incident_ack: '确认事件',
    create_user: '创建用户', update_user: '更新用户', reset_password: '重置密码', delete_user: '删除用户',
    killed: '已终止', suggested: '建议操作',
  }
  if (!type) return '-'
  if (type.startsWith('agent_command:')) return '远程命令: ' + type.substring('agent_command:'.length)
  if (type.startsWith('import:')) return '导入: ' + type.substring('import:'.length)
  return labels[type] || type || '-'
}

function formatTime(ts: string): string {
  if (!ts) return '-'
  return dayjs(ts).format('HH:mm:ss')
}

function formatRelativeTime(ts: string): string {
  if (!ts) return '-'
  const diff = Date.now() - new Date(ts).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins} 分钟前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} 小时前`
  return `${Math.floor(hours / 24)} 天前`
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

// 计算基线：取历史数据的平均值作为基线
function calcBaseline(history: { value: number }[]): number {
  if (history.length === 0) return 0
  const sum = history.reduce((a, h) => a + h.value, 0)
  return Math.round(sum / history.length)
}

// ═══════════════════════════════════════════════════
// 数据获取
// ═══════════════════════════════════════════════════
async function fetchData() {
  fetchError.value = false
  try {
    const [statusResp, alertsResp, safetyResp, guardsResp, healthResp, sitesResp, insightsResp] = await Promise.all([
      axios.get('/api/status'),
      axios.get('/api/alerts'),
      axios.get('/api/safety'),
      axios.get('/api/guards'),
      axios.get('/api/health/score'),
      axios.get('/api/probe/sites'),
      axios.get('/api/insights'),
    ])
    metrics.value = statusResp.data
    alerts.value = alertsResp.data.alerts || []
    safety.value = safetyResp.data
    guards.value = guardsResp.data.guards || []
    healthScore.value = healthResp.data
    sites.value = sitesResp.data.sites || []
    insights.value = insightsResp.data

    // 推入时序数据
    const now = dayjs().format('HH:mm:ss')
    const cpuBaseline = calcBaseline(cpuHistory.value)
    const memBaseline = calcBaseline(memHistory.value)
    const diskBaseline = calcBaseline(diskHistory.value)

    cpuHistory.value.push({ time: now, value: cpuPercent.value, baseline: cpuBaseline || 30 })
    memHistory.value.push({ time: now, value: memPercent.value, baseline: memBaseline || 40 })
    diskHistory.value.push({ time: now, value: diskPercent.value, baseline: diskBaseline || 50 })

    const netSentVal = Number((netSent.value / 1024).toFixed(0))
    const netRecvVal = Number((netRecv.value / 1024).toFixed(0))
    netHistory.value.push({ time: now, sent: netSentVal, recv: netRecvVal, baseline: 0 })

    // 更新上次采样值，供下个周期计算增量
    prevNetSent = metrics.value?.net_bytes_sent || 0
    prevNetRecv = metrics.value?.net_bytes_recv || 0

    // 限制历史长度
    if (cpuHistory.value.length > MAX_HISTORY) cpuHistory.value.shift()
    if (memHistory.value.length > MAX_HISTORY) memHistory.value.shift()
    if (diskHistory.value.length > MAX_HISTORY) diskHistory.value.shift()
    if (netHistory.value.length > MAX_HISTORY) netHistory.value.shift()

    // 更新学习进度（简化：基于是否有扣分项判断）
    if (healthScore.value?.deductions?.length === 0 && healthScore.value?.total === 100) {
      learnProgress.value = Math.min(100, learnProgress.value + 5)
    } else {
      learnProgress.value = 100
    }

    loading.value = false
  } catch (err) {
    console.error('获取数据失败:', err)
    fetchError.value = true
loading.value = false
}
}

// ═══════════════════════════════════════════════════
// TOP 进程获取
// ═══════════════════════════════════════════════════
async function fetchTopProcesses() {
  loadingTopProc.value = true
  try {
    const resp = await axios.get('/api/top-processes?limit=10')
    topCPUProcesses.value = resp.data.top_cpu || resp.data.cpu || []
    topMemProcesses.value = resp.data.top_mem || resp.data.memory || []
  } catch {
    // 静默失败
  } finally {
    loadingTopProc.value = false
  }
}

// ═══════════════════════════════════════════════════
// 安全更新（CVE Feed Monitor）
// ═══════════════════════════════════════════════════
async function fetchSecurityUpdates() {
  try {
    const resp = await axios.get('/api/security-updates')
    securityUpdates.value = resp.data
  } catch {
    // 静默失败
  }
}

async function triggerSecurityCheck() {
  securityUpdatesLoading.value = true
  try {
    await axios.post('/api/security-updates/check')
    // 延迟 3 秒后刷新结果
    setTimeout(() => {
      fetchSecurityUpdates()
      securityUpdatesLoading.value = false
    }, 3000)
  } catch {
    securityUpdatesLoading.value = false
  }
}

const hasSecurityUpdates = computed(() => {
  if (!securityUpdates.value) return false
  return (securityUpdates.value.matched_cves?.length > 0) ||
         (securityUpdates.value.pending_updates?.length > 0)
})

const securityUpdatesSummary = computed(() => {
  if (!securityUpdates.value) return ''
  const cveCount = securityUpdates.value.matched_cves?.length || 0
  const updateCount = securityUpdates.value.pending_updates?.length || 0
  const parts = []
  if (cveCount > 0) parts.push(`${cveCount} 个CVE`)
  if (updateCount > 0) parts.push(`${updateCount} 个补丁`)
  return parts.join(' · ')
})

const securityUpdatesTagType = computed(() => {
  if (!securityUpdates.value) return 'info'
  if (securityUpdates.value.critical_cve_count > 0 || securityUpdates.value.critical_updates > 0) return 'danger'
  if (securityUpdates.value.high_cve_count > 0 || securityUpdates.value.important_updates > 0) return 'warning'
  return 'info'
})

const securityUpdatesIconClass = computed(() => {
  if (!securityUpdates.value) return ''
  if (securityUpdates.value.critical_cve_count > 0 || securityUpdates.value.critical_updates > 0) return 'icon-danger'
  if (securityUpdates.value.high_cve_count > 0 || securityUpdates.value.important_updates > 0) return 'icon-warning'
  return 'icon-info'
})

function cveTagType(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'danger'
    case 'high': return 'danger'
    case 'medium': return 'warning'
    case 'low': return 'info'
    default: return 'info'
  }
}

function updateTagType(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'danger'
    case 'important': case 'high': return 'warning'
    case 'moderate': case 'medium': return 'info'
    case 'low': return 'success'
    default: return 'info'
  }
}

function updateSeverityLabel(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return '严重'
    case 'important': case 'high': return '重要'
    case 'moderate': case 'medium': return '中等'
    case 'low': return '低'
    default: return severity || '未知'
  }
}

function truncateText(text: string, maxLen: number) {
  if (!text) return ''
  return text.length > maxLen ? text.substring(0, maxLen) + '...' : text
}

// ═══════════════════════════════════════════════════
// 生命周期
// ═══════════════════════════════════════════════════
onMounted(() => {
  fetchData()
  fetchTopProcesses()
  fetchSecurityUpdates()
  timer = setInterval(fetchData, 15000)
  topProcTimer = setInterval(fetchTopProcesses, 30000)
  // 安全更新检查：每 10 分钟刷新一次缓存状态
  setInterval(fetchSecurityUpdates, 10 * 60 * 1000)
})

onUnmounted(() => {
  if (timer) { clearInterval(timer); timer = null }
  if (topProcTimer) { clearInterval(topProcTimer); topProcTimer = null }
})
</script>

<style scoped>
/* ═══ 作战日志卡片 ═══ */
.battle-log-card {
  border-left: 4px solid #52c41a;
}
.battle-log-card :deep(.el-card__body) {
  padding: 16px 20px;
}
.battle-log-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.battle-log-title {
  font-weight: 700;
  font-size: 16px;
  color: var(--sg-text-1, #303133);
  display: flex;
  align-items: center;
  gap: 6px;
}
.battle-log-body {
  min-height: 40px;
}
.battle-log-items {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
.battle-log-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  border-radius: 8px;
  background: var(--sg-bg-2, #f5f7fa);
  min-width: 120px;
}
.battle-log-ban {
  background: linear-gradient(135deg, #fff1f0 0%, #ffe1e1 100%);
}
.battle-log-clean {
  background: linear-gradient(135deg, #e6f7ff 0%, #d4edda 100%);
}
.battle-log-disk {
  background: linear-gradient(135deg, #f6ffed 0%, #e8f5e9 100%);
}
.battle-log-cert {
  background: linear-gradient(135deg, #f6ffed 0%, #e3f2fd 100%);
}
.battle-log-restart {
  background: linear-gradient(135deg, #fffbe6 0%, #fff7e6 100%);
}
.battle-log-kill {
  background: linear-gradient(135deg, #fff1f0 0%, #ffe8e8 100%);
}
.battle-log-nginx {
  background: linear-gradient(135deg, #e6f7ff 0%, #e3f2fd 100%);
}
.bl-content {
  display: flex;
  flex-direction: column;
}
.bl-number {
  font-size: 22px;
  font-weight: 800;
  color: var(--sg-text-1, #303133);
  line-height: 1.2;
}
.bl-label {
  font-size: 12px;
  color: var(--sg-text-2, #606266);
}
.battle-log-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 12px;
  padding-top: 8px;
  border-top: 1px solid var(--sg-border, #ebeef5);
}
.bl-rate {
  font-size: 13px;
  color: var(--sg-text-2, #606266);
}
.bl-rate strong {
  font-size: 15px;
  font-weight: 700;
}
.bl-link {
  color: var(--sg-primary, #409eff);
  cursor: pointer;
  font-size: 13px;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.bl-link:hover {
  opacity: 0.8;
}
.battle-log-empty {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 0;
}
.battle-log-empty span {
  font-size: 14px;
  color: var(--sg-text-2, #606266);
}

/* ═══ 智能洞察横条 ═══ */
.insights-card :deep(.el-card__body) {
  padding: 10px 16px;
}
.insights-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 18px;
  font-size: 13px;
  line-height: 1.6;
}
.insights-title {
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--el-text-color-primary);
}
.insight-item {
  color: var(--el-text-color-regular);
}
.insight-ok {
  color: #67c23a;
}
.insight-warn {
  color: #e6a23c;
}
.insight-bad {
  color: #f56c6c;
}
.insight-muted {
  color: var(--el-text-color-secondary);
}

/* ═══ 全局布局 ═══ */
.dashboard {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

/* ═══ CSS 变量：覆盖 Element Plus 默认色 ═══ */
.dashboard {
  --sg-green: #22c55e;
  --sg-yellow: #f59e0b;
  --sg-red: #ef4444;
  --sg-blue: #4c6fff;
  --sg-gray: #c0c4cc;
  --sg-bg: #f3f5fa;
  --sg-card-radius: 12px;
  --sg-transition: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

/* 入场动画：卡片依次浮入 */
@keyframes dash-fade-up {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
.health-card,
.deductions-panel,
.dashboard > .el-row {
  animation: dash-fade-up 0.4s cubic-bezier(0.4, 0, 0.2, 1) both;
}
.dashboard > .el-row:nth-of-type(2) { animation-delay: 0.06s; }
.dashboard > .el-row:nth-of-type(3) { animation-delay: 0.12s; }
.dashboard > .el-row:nth-of-type(4) { animation-delay: 0.18s; }

/* ═══ 健康评分卡片 ═══ */
.health-card {
  margin-bottom: 16px;
  cursor: pointer;
  transition: box-shadow var(--sg-transition), transform var(--sg-transition);
  background:
    radial-gradient(ellipse 60% 120% at 8% 0%, rgba(76, 111, 255, 0.05), transparent 60%),
    var(--sg-bg-card);
}
.health-card:hover {
  box-shadow: 0 12px 32px rgba(15, 23, 42, 0.1);
  transform: translateY(-2px);
}

.health-content {
  display: flex;
  align-items: center;
  gap: 32px;
  flex-wrap: wrap;
}

.health-gauge {
  flex-shrink: 0;
}

.health-summary {
  flex: 1;
  min-width: 200px;
}
.health-score-num {
  font-size: 52px;
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: -0.02em;
  transition: color var(--sg-transition);
}
.health-score-num.pulse {
  animation: score-pulse 1.5s ease-in-out infinite;
}
.health-score-unit {
  font-size: 18px;
  font-weight: 400;
  color: #94a3b8;
  margin-left: 4px;
}
.health-trend {
  font-size: 13px;
  font-weight: 600;
  margin-top: 4px;
}
.health-explain {
  font-size: 14px;
  color: var(--sg-text-2);
  margin-top: 8px;
  line-height: 1.6;
  max-width: 400px;
}

.health-sub-scores {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 200px;
  padding: 14px 16px;
  background: var(--sg-fill-1);
  border-radius: 12px;
  border: 1px solid var(--sg-border-light);
}
.sub-item {
  display: flex;
  align-items: center;
  gap: 10px;
}
.sub-label {
  font-size: 13px;
  color: var(--sg-text-3);
  min-width: 42px;
  font-weight: 500;
}
.sub-val {
  font-size: 13px;
  font-weight: 700;
  min-width: 28px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

/* 健康分 < 50 脉冲动画 */
@keyframes score-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.7; transform: scale(1.03); }
}

/* ═══ 扣分明细面板 ═══ */
.deductions-panel {
  margin-bottom: 16px;
}
.deduction-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: background var(--sg-transition), transform var(--sg-transition);
}
.deduction-row:hover {
  background: var(--sg-fill-2);
  transform: translateX(3px);
}
.deduction-row:hover .deduction-arrow {
  color: var(--sg-blue);
  transform: translateX(2px);
}
.deduction-reason {
  flex: 1;
  font-size: 13px;
  color: var(--sg-text-2);
}
.deduction-points {
  font-size: 13px;
  color: var(--sg-red);
  font-weight: 700;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
.deduction-arrow {
  color: #c0c4cc;
  font-size: 12px;
  transition: all var(--sg-transition);
}

/* ═══ 资源迷你图表卡片 ═══ */
.mini-chart-card {
  margin-bottom: 0;
  transition: box-shadow var(--sg-transition), transform var(--sg-transition);
}
.mini-chart-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 28px rgba(15, 23, 42, 0.09);
}
.mini-chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
}
.mini-chart-header > span:first-child {
  color: var(--sg-text-2);
  font-weight: 600;
}
.mini-chart-footer {
  margin-top: 6px;
  font-size: 12px;
  color: var(--sg-text-3);
  text-align: center;
  font-variant-numeric: tabular-nums;
}

/* ═══ 守护状态卡片 ═══ */
.guard-card {
  transition: all var(--sg-transition);
  border: 1px solid var(--sg-border);
  border-radius: 10px;
}
.guard-card:hover {
  border-color: #a5b5ff;
  box-shadow: 0 4px 14px rgba(76, 111, 255, 0.1);
  transform: translateY(-2px);
}
.guard-card.guard-abnormal {
  border-color: var(--sg-red);
  animation: guard-pulse 1.5s ease-in-out infinite;
}
@keyframes guard-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.3); }
  50% { box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); }
}

.guard-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}
.guard-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--sg-text-1);
}
.guard-card-desc {
  font-size: 12px;
  color: var(--sg-text-3);
  line-height: 1.5;
}

.guard-events {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--sg-border-light);
}
.guard-event-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  font-size: 12px;
}
.guard-event-text {
  flex: 1;
  color: var(--sg-text-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.guard-event-time {
  color: var(--sg-text-3);
  font-size: 11px;
  white-space: nowrap;
}
.guard-no-events {
  font-size: 12px;
  color: var(--sg-text-3);
  text-align: center;
  padding: 8px 0;
}

/* ═══ 事件流 ═══ */
.event-card {
  height: 100%;
}
.event-card :deep(.el-card__body) {
  padding: 14px;
}
.event-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  max-height: 400px;
  overflow-y: auto;
  padding-right: 6px;
}
.event-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 11px 12px;
  border-radius: 10px;
  border: 1px solid transparent;
  transition: background var(--sg-transition), border-color var(--sg-transition);
}
.event-item:hover {
  background: var(--sg-fill-hover);
}
.event-item.event-unread {
  background: var(--sg-unread-bg);
}
.event-item.event-unread:hover {
  background: var(--sg-unread-hover-bg);
}
.event-item.event-clickable {
  cursor: pointer;
}
.event-message {
  font-size: 12px;
  color: var(--sg-text-3);
  margin-top: 2px;
  line-height: 1.4;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.event-time-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 2px;
}
.event-link {
  font-size: 11px;
  display: inline-flex;
  align-items: center;
  gap: 2px;
}
.event-body {
  flex: 1;
  min-width: 0;
}
.event-title-row {
  display: flex;
  align-items: center;
  gap: 6px;
  justify-content: space-between;
}
.event-text {
  font-size: 13px;
  color: var(--sg-text-1);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.event-time {
  font-size: 11px;
  color: var(--sg-text-3);
  margin-top: 2px;
  font-variant-numeric: tabular-nums;
}

/* ═══ 网站存活性监控 ═══ */
.sites-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.site-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  margin: 0 -4px;
  border-radius: 8px;
  border-bottom: 1px solid var(--sg-border-light);
  transition: background var(--sg-transition);
}
.site-item:hover { background: var(--sg-fill-hover); }
.site-item:last-child { border-bottom: none; }
.site-light {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}
.site-light.green { background: var(--sg-green); box-shadow: 0 0 6px rgba(34, 197, 94, 0.6); }
.site-light.red { background: var(--sg-red); box-shadow: 0 0 6px rgba(239, 68, 68, 0.6); animation: guard-pulse 1.5s infinite; }
.site-light.gray { background: var(--sg-gray); }
.site-name { font-weight: 600; min-width: 80px; font-size: 13px; color: var(--sg-text-1); }
.site-latency { font-size: 12px; color: var(--sg-green); font-variant-numeric: tabular-nums; }
.site-latency.error { color: var(--sg-red); }

/* ═══ 通用 ═══ */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

/* ═══ 安全更新提醒卡片 ═══ */
.security-updates-card {
  border: 1px solid var(--sg-border);
  border-radius: 10px;
}
.security-updates-card :deep(.el-card__body) {
  padding: 12px 16px;
}
.security-updates-row {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.security-updates-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 600;
  color: var(--sg-text-1);
}
.security-updates-title .el-icon {
  font-size: 18px;
}
.security-updates-title .icon-danger { color: var(--sg-red); }
.security-updates-title .icon-warning { color: var(--sg-orange); }
.security-updates-title .icon-info { color: var(--sg-blue); }
.security-updates-body {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.security-updates-section {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.security-updates-section-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--sg-text-2);
  margin-bottom: 2px;
}
.security-update-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  font-size: 13px;
  color: var(--sg-text-2);
  border-bottom: 1px solid var(--sg-border-light);
}
.security-update-item:last-child { border-bottom: none; }
.cve-id {
  font-weight: 600;
  color: var(--sg-text-1);
  font-family: monospace;
}
.cve-product {
  color: var(--sg-blue);
  font-weight: 500;
}
.cve-desc {
  flex: 1;
  color: var(--sg-text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.cve-link {
  color: var(--sg-blue);
  text-decoration: none;
  font-size: 12px;
}
.cve-link:hover { text-decoration: underline; }
.pkg-name {
  font-weight: 600;
  color: var(--sg-text-1);
}
.pkg-version {
  color: var(--sg-green);
  font-family: monospace;
}
.pkg-advisory {
  color: var(--sg-text-3);
  font-size: 12px;
}
.more-items {
  font-size: 12px;
  color: var(--sg-text-3);
  padding: 2px 0;
}
.security-updates-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 4px;
}
.security-updates-hint {
  font-size: 12px;
  color: var(--sg-text-3);
}
</style>
