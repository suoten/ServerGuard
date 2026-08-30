<template>
  <div>
    <el-card>
      <template #header><span>系统设置</span></template>
      <el-tabs>
        <el-tab-pane label="基本配置">
          <el-form label-width="140px" v-loading="loading">
            <el-form-item label="采集间隔">
              <el-input-number v-model="settings.collect_interval" :min="1" :max="60" /> 秒
            </el-form-item>
            <el-form-item label="运行模式">
              <el-switch v-model="settings.learn_mode" active-text="只告警不修复" inactive-text="自动修复" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">学习模式下只观察告警，不执行修复操作</span>
            </el-form-item>
            <el-form-item label="最大内存">
              <el-input-number v-model="settings.max_memory_mb" :min="32" :max="512" /> MB
              <span style="margin-left: 10px; color: #909399; font-size: 12px">Agent 自身内存上限</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="通知设置">
          <el-form label-width="140px" v-loading="notifyLoading">
            <el-divider content-position="left">WxPusher 推送（免费多平台）</el-divider>
            <el-form-item label="AppToken">
              <el-input v-model="notify.wxpusher_app_token" placeholder="APP_xxx，从 WxPusher 后台获取" show-password />
            </el-form-item>
            <el-form-item label="UID">
              <el-input v-model="notify.wxpusher_uid" placeholder="UID_xxx，扫码关注应用后获取" show-password />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">
                <a href="https://wxpusher.zjiecode.com/admin/" target="_blank" style="color: #409eff">点击前往 WxPusher 后台</a>，创建应用获取 AppToken，扫码关注后获取 UID
              </span>
            </el-form-item>

            <el-divider content-position="left">邮件推送</el-divider>
            <el-form-item label="SMTP 服务器">
              <el-input v-model="notify.smtp_host" placeholder="smtp.gmail.com" />
            </el-form-item>
            <el-form-item label="SMTP 端口">
              <el-input v-model="notify.smtp_port" placeholder="587" style="width: 120px" />
            </el-form-item>
            <el-form-item label="发件邮箱">
              <el-input v-model="notify.smtp_user" placeholder="sender@gmail.com" />
            </el-form-item>
            <el-form-item label="邮箱密码">
              <el-input v-model="notify.smtp_password" type="password" placeholder="密码或应用专用密码" show-password />
            </el-form-item>
            <el-form-item label="收件邮箱">
              <el-input v-model="notify.email_to" placeholder="admin@example.com（多个用逗号分隔）" />
            </el-form-item>

            <el-divider content-position="left">每日巡检报告</el-divider>
            <el-form-item label="巡检报告推送">
              <el-switch v-model="notify.digest_enabled" active-text="开启" inactive-text="关闭" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每天定时推送巡检报告（健康评分/资源峰值/网站/证书/告警/自愈汇总）</span>
            </el-form-item>
            <el-form-item label="报告推送时间">
              <el-input-number v-model="notify.digest_hour" :min="0" :max="23" /> 点
            </el-form-item>
            <el-form-item label="报告预览">
              <el-button @click="previewReport" :loading="reportLoading">在线预览</el-button>
              <el-button type="primary" plain @click="sendReportNow" :loading="reportSending">立即发送到所有渠道</el-button>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" @click="saveNotify" :loading="notifySaving">保存通知设置</el-button>
              <el-button @click="testNotify" :loading="testing">发送测试通知</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="面板密码">
          <el-form label-width="140px">
            <el-form-item label="登录用户名">
              <el-input v-model="settings.username" placeholder="admin" />
            </el-form-item>
            <el-form-item label="新密码">
              <el-input v-model="newPassword" type="password" placeholder="留空则不修改" show-password />
            </el-form-item>
            <el-form-item label="确认密码">
              <el-input v-model="confirmPassword" type="password" placeholder="再次输入新密码" show-password />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="savePassword" :loading="saving">保存密码</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="证书配置">
          <el-form label-width="140px">
            <el-form-item label="自动续期天数">
              <el-input-number v-model="settings.auto_renew_days" :min="1" :max="30" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">证书剩余天数低于此值时自动续期</span>
            </el-form-item>
            <el-form-item label="证书扫描端口">
              <el-input v-model="certPortsStr" placeholder="443, 8443" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">扫描这些端口上的 HTTPS 证书</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="安全设置">
          <el-form label-width="140px">
            <el-form-item label="进程关闭上限（每小时）">
              <el-input-number v-model="settings.kill_budget_hourly" :min="0" :max="50" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每小时最多关闭进程次数</span>
            </el-form-item>
            <el-form-item label="进程关闭上限（每天）">
              <el-input-number v-model="settings.kill_budget_daily" :min="0" :max="100" />
              <span style="margin-left: 10px; color: #909399; font-size: 12px">每天最多关闭进程次数</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveSettings" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- AI 增强 -->
        <el-tab-pane label="AI 增强">
          <el-form label-width="140px" v-loading="llmLoading">
            <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px">
              AI 增强层将告警转化为人性化描述，生成智能周报，并为故障事件提供根因分析。
            </el-alert>
            <el-form-item label="LLM 状态">
              <el-tag :type="llmStatus?.enabled ? 'success' : 'info'" effect="dark">
                {{ llmStatus?.enabled ? '✅ 已启用' : '⚪ 未配置' }}
              </el-tag>
            </el-form-item>
            <el-form-item label="Provider">
              <el-select v-model="llmConfig.provider" placeholder="选择 LLM 提供商">
                <el-option label="OpenAI (GPT-4o-mini)" value="openai" />
                <el-option label="DeepSeek" value="deepseek" />
                <el-option label="Moonshot (Kimi)" value="moonshot" />
                <el-option label="本地 Ollama" value="ollama" />
                <el-option label="禁用" value="" />
              </el-select>
            </el-form-item>
            <el-form-item label="API Key">
              <el-input v-model="llmConfig.apiKey" placeholder="sk-..." show-password />
            </el-form-item>
            <el-form-item label="API Base">
              <el-input v-model="llmConfig.apiBase" placeholder="https://api.openai.com/v1" />
            </el-form-item>
            <el-form-item label="模型名">
              <el-input v-model="llmConfig.model" placeholder="gpt-4o-mini" />
            </el-form-item>
            <el-divider content-position="left">功能开关</el-divider>
            <el-form-item label="告警人性化">
              <el-switch v-model="llmConfig.humanizeAlert" />
              <span style="margin-left: 8px; color: #909399; font-size: 12px">将原始告警转为“人话”描述</span>
            </el-form-item>
            <el-form-item label="智能周报">
              <el-switch v-model="llmConfig.weeklyReport" />
              <span style="margin-left: 8px; color: #909399; font-size: 12px">每周自动生成运维总结</span>
            </el-form-item>
            <el-form-item label="故障解释">
              <el-switch v-model="llmConfig.explainIncident" />
              <span style="margin-left: 8px; color: #909399; font-size: 12px">为故障事件提供 AI 根因分析</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveLLM" :loading="llmSaving">保存 AI 配置</el-button>
              <el-button @click="testLLM" :loading="llmTesting">发送测试请求</el-button>
            </el-form-item>
            <el-form-item v-if="llmTestResult" label="测试结果">
              <el-alert :type="llmTestResult.type" :title="llmTestResult.text" :closable="false" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 双向通知 -->
        <el-tab-pane label="双向通知">
          <el-form label-width="140px" v-loading="biNotifyLoading">
            <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 16px">
              ⚡ 开启双向交互后，告警附短编号，手机回复指令即可远程控制自动修复。
            </el-alert>
            <el-form-item label="双向交互">
              <el-switch v-model="biNotify.enabled" active-text="开启" inactive-text="关闭" />
            </el-form-item>
            <el-form-item label="远程暂停状态">
              <el-tag :type="safetyStatus?.remotePaused ? 'warning' : 'success'" effect="dark" size="large">
                {{ safetyStatus?.remotePaused ? '⏸ 已暂停' : '▶ 运行中' }}
              </el-tag>
              <el-button v-if="safetyStatus?.remotePaused" size="small" type="success" @click="remoteResume" :loading="remoteLoading" style="margin-left: 12px">
                恢复自动修复
              </el-button>
              <el-button v-else size="small" type="warning" @click="remotePause" :loading="remoteLoading" style="margin-left: 12px">
                暂停自动修复
              </el-button>
            </el-form-item>
            <el-divider content-position="left">待回复告警</el-divider>
            <el-table :data="pendingAlerts.slice((pendingPage-1)*pendingSize, pendingPage*pendingSize)" stripe size="small" v-loading="pendingLoading">
              <el-table-column label="编号" width="90" prop="shortCode" />
              <el-table-column label="告警" min-width="200" show-overflow-tooltip prop="title" />
              <el-table-column label="级别" width="80">
                <template #default="{ row }">
                  <el-tag :type="row.level === 'critical' ? 'danger' : 'warning'" size="small">{{ levelText(row.level) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="时间" width="140">
                <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
              </el-table-column>
              <el-table-column label="操作" width="180" fixed="right">
                <template #default="{ row }">
                  <el-button size="small" type="warning" @click="pauseFor(row)" :loading="row._loading">暂停</el-button>
                  <el-button size="small" type="success" @click="ackFor(row)" :loading="row._loading">确认</el-button>
                </template>
              </el-table-column>
</el-table>
<div style="margin-top: 12px; display: flex; justify-content: flex-end">
<el-pagination v-model:current-page="pendingPage" v-model:page-size="pendingSize" :page-sizes="[10, 20, 50, 100]" :total="pendingAlerts.length" layout="total, sizes, prev, pager, next" />
</div>
<el-empty v-if="!pendingLoading && pendingAlerts.length === 0" description="暂无待回复告警" />
          </el-form>
        </el-tab-pane>

        <!-- 多服务器管理 -->
        <el-tab-pane label="多服务器管理">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px">
            ServerGuard 支持多服务器集中管理。在中心节点运行 Hub，各服务器 Agent 连接到 Hub，即可在一个面板查看所有服务器的状态、告警和安全事件。
          </el-alert>

          <el-divider content-position="left">Hub 状态</el-divider>
          <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
            <el-descriptions-item label="Hub 组件">
              <el-tag v-if="hubComponent?.installed" type="success" effect="dark" size="small">已安装</el-tag>
              <el-tag v-else type="info" size="small">未安装</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="Hub 运行状态">
              <el-tag v-if="hubConnected" type="success" effect="dark" size="small">已连接</el-tag>
              <el-tag v-else type="info" size="small">未连接</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="已管理服务器数">
              <span style="font-weight: 600; font-size: 16px; color: #409eff">{{ serverCount }}</span> 台
            </el-descriptions-item>
            <el-descriptions-item label="当前模式">
              <el-tag v-if="serverCount > 1" type="warning" effect="dark" size="small">多机集中管控</el-tag>
              <el-tag v-else type="info" size="small">单机模式</el-tag>
            </el-descriptions-item>
          </el-descriptions>

          <el-divider content-position="left">部署 Hub（中心节点）</el-divider>
          <div class="deploy-steps">
            <div class="deploy-step">
              <span class="step-num">1</span>
              <div class="step-body">
                <div class="step-title">在中心节点安装 ServerGuard</div>
                <div class="step-desc">在选定作为 Hub 的服务器上安装 ServerGuard Agent（和单机部署一样）。</div>
              </div>
            </div>
            <div class="deploy-step">
              <span class="step-num">2</span>
              <div class="step-body">
                <div class="step-title">启动 Hub 服务</div>
                <div class="step-desc">Hub 已随 Agent 一起安装，执行以下命令启动：</div>
                <pre class="cmd-block"># 设置 Hub 密钥（用于 Agent 认证）
echo 'hub_token: YourSecretToken2024' >> /opt/serverguard/config.yaml

# 启动 Hub
systemctl start serverguard-hub
systemctl enable serverguard-hub

# 查看 Hub 监听端口（默认 8443）
ss -tlnp | grep 8443</pre>
              </div>
            </div>
            <div class="deploy-step">
              <span class="step-num">3</span>
              <div class="step-body">
                <div class="step-title">在每台被管理服务器上配置 Agent 连接 Hub</div>
                <div class="step-desc">在被管理的服务器上，编辑 Agent 配置文件，启用 Hub 连接：</div>
                <pre class="cmd-block"># 编辑 Agent 配置
cat >> /opt/serverguard/config.yaml << 'EOF'
hub:
  enabled: true
  url: "ws://HUB服务器IP:8443/ws/agent"
  token: "YourSecretToken2024"  # 与 Hub 端一致
  agent_id: ""  # 留空则自动生成
EOF

# 重启 Agent 使配置生效
systemctl restart serverguard</pre>
              </div>
            </div>
            <div class="deploy-step">
              <span class="step-num">4</span>
              <div class="step-body">
                <div class="step-title">验证连接</div>
                <div class="step-desc">在 Hub 面板的<a router-link to="/servers">服务器列表</a>中，应能看到所有已连接的 Agent。也可以用 sgctl 验证：</div>
                <pre class="cmd-block"># 在任意服务器上执行
sgctl -s http://127.0.0.1:8443 status
sgctl -s http://127.0.0.1:8443 hub servers</pre>
              </div>
            </div>
          </div>

          <el-divider content-position="left">Hub 能力说明</el-divider>
          <el-table :data="hubFeatures" stripe size="small">
            <el-table-column label="功能" prop="name" width="180" />
            <el-table-column label="说明" prop="desc" />
          </el-table>
        </el-tab-pane>

        <!-- 命令行工具 (sgctl) -->
        <el-tab-pane label="命令行工具">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px">
            sgctl 是 ServerGuard 的命令行运维工具，已安装在 <code>/opt/serverguard/sgctl</code>。适合在 SSH 终端中使用，支持状态查询、安全控制、配置管理、数据导出等操作。
          </el-alert>

          <el-divider content-position="left">常用命令</el-divider>
          <el-table :data="sgctlCommands" stripe size="small">
            <el-table-column label="命令" width="280">
              <template #default="{ row }">
                <code class="cmd-text">{{ row.cmd }}</code>
              </template>
            </el-table-column>
            <el-table-column label="说明" prop="desc" />
          </el-table>

          <el-divider content-position="left">使用示例</el-divider>
          <div class="cmd-examples">
            <div class="cmd-example">
              <div class="cmd-example-title">查看当前服务器状态</div>
              <pre class="cmd-block">sgctl status</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">系统诊断（检查 Agent 健康、配置、端口等）</div>
              <pre class="cmd-block">sgctl doctor</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">紧急停止所有自动修复（只监控不操作）</div>
              <pre class="cmd-block">sgctl emergency-stop
# 恢复
sgctl emergency-resume</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">查看安全发现项</div>
              <pre class="cmd-block">sgctl finding list</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">配置版本管理</div>
              <pre class="cmd-block"># 查看配置版本列表
sgctl config-version list

# 回滚到指定版本
sgctl config-version rollback &lt;version-id&gt;

# 导出当前配置
sgctl config-version export > backup.yaml

# 导入配置
sgctl config-version import backup.yaml</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">数据导出</div>
              <pre class="cmd-block"># 导出最近30天指标为 CSV
sgctl export metrics --format csv --hours 720 --output metrics.csv

# 导出告警记录
sgctl export alerts --hours 168 --output alerts.json</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">从其他工具迁移配置</div>
              <pre class="cmd-block"># 从宝塔迁移
sgctl import baota --path /www/server/panel

# 从 Supervisor 迁移
sgctl import supervisor --path /etc/supervisor/conf.d

# 从 systemd 迁移
sgctl import systemd

# 从 PM2 迁移
sgctl import pm2

# 从 Monit 迁移
sgctl import monit --path /etc/monit/monitrc</pre>
            </div>
            <div class="cmd-example">
              <div class="cmd-example-title">连接到远程 Hub 管理</div>
              <pre class="cmd-block"># 指定 Hub 地址查询多机状态
sgctl -s http://HUB_IP:8443 status
sgctl -s http://HUB_IP:8443 finding list

# 输出 JSON 格式（方便脚本处理）
sgctl -s http://HUB_IP:8443 -j status | jq .</pre>
            </div>
          </div>

          <el-divider content-position="left">提示</el-divider>
          <el-alert type="warning" :closable="false" show-icon>
            <ul style="margin: 0; padding-left: 20px">
              <li>sgctl 默认连接本机 <code>http://127.0.0.1:8443</code>，用 <code>-s</code> 指定远程地址</li>
              <li>用 <code>-j</code> 或 <code>--json</code> 输出 JSON 格式，适合脚本化处理</li>
              <li>所有操作都会记录在审计日志中，可在面板的「操作日志」页面查看</li>
              <li>sgctl 与 Agent 版本一致，升级 Agent 后 sgctl 也会同步更新</li>
            </ul>
          </el-alert>
        </el-tab-pane>

        <!-- 组件信息 -->
        <el-tab-pane label="组件信息">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom: 16px">
            ServerGuard 包含三个组件。Agent 是核心（当前运行中），Hub 用于多服务器集中管理，sgctl 是命令行运维工具。
          </el-alert>
          <el-table :data="components" stripe v-loading="componentsLoading">
            <el-table-column label="组件" width="160">
              <template #default="{ row }">
                <span style="font-weight: 600">{{ row.display_name }}</span>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.running" type="success" effect="dark" size="small">运行中</el-tag>
                <el-tag v-else-if="row.installed" type="info" effect="dark" size="small">已安装</el-tag>
                <el-tag v-else type="info" size="small">未安装</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="说明" min-width="240">
              <template #default="{ row }">{{ row.description }}</template>
            </el-table-column>
            <el-table-column label="路径" min-width="280">
              <template #default="{ row }"><code style="font-size: 12px; color: #909399">{{ row.path }}</code></template>
            </el-table-column>
          </el-table>
          <el-divider content-position="left">组件说明</el-divider>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="serverguard-agent">
              核心组件，包含监控采集、安全扫描（网站安全/漏洞扫描/攻击预警/服务器安全）、自动修复引擎和 Web 面板。单台服务器只需安装 Agent。
            </el-descriptions-item>
            <el-descriptions-item label="serverguard-hub">
              多服务器管理中枢。当有多台服务器时，在中心节点运行 Hub，各服务器 Agent 连接到 Hub，实现集中告警查看和统一管理。单台服务器不需要运行 Hub。
            </el-descriptions-item>
            <el-descriptions-item label="sgctl">
              命令行运维工具。支持状态查询（sgctl status）、系统诊断（sgctl doctor）、版本升级（sgctl upgrade）、配置导入（sgctl import）等操作。适合在 SSH 终端中使用。
            </el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <!-- 巡检报告预览对话框 -->
    <el-dialog v-model="reportDialogVisible" title="每日巡检报告预览" width="560px">
      <pre class="report-preview">{{ reportContent }}</pre>
      <template #footer>
        <el-button @click="reportDialogVisible = false">关闭</el-button>
        <el-button type="primary" @click="sendReportNow" :loading="reportSending">发送到所有渠道</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'
import dayjs from 'dayjs'

const loading = ref(false)
const saving = ref(false)
const newPassword = ref('')
const confirmPassword = ref('')
const certPortsStr = ref('443, 8443')

const notifyLoading = ref(false)
const notifySaving = ref(false)
const testing = ref(false)

// ─── 组件信息 ───
const components = ref<any[]>([])
const componentsLoading = ref(false)

// ─── 多服务器管理 ───
const hubComponent = ref<any>(null)
const hubConnected = ref(false)
const serverCount = ref(1)
const hubFeatures = [
  { name: '集中状态监控', desc: '在一个面板查看所有服务器的 CPU、内存、磁盘、健康评分' },
  { name: '统一告警视图', desc: '所有服务器的告警汇总到 Hub，统一通知和分级处理' },
  { name: '远程安全控制', desc: '远程暂停/恢复自动修复、紧急停止，无需逐台登录' },
  { name: '多机安全扫描', desc: '集中查看所有服务器的安全发现项和攻击预警' },
  { name: 'Agent 远程重启', desc: '从 Hub 面板远程重启任意服务器的 Agent' },
  { name: '证书集中管理', desc: '汇总所有服务器的证书到期状态，统一续期' },
]

async function fetchHubStatus() {
  try {
    const [versionResp, statusResp, serversResp] = await Promise.all([
      axios.get('/api/version'),
      axios.get('/api/status'),
      axios.get('/api/servers'),
    ])
    const comps = versionResp.data.components || []
    hubComponent.value = comps.find((c: any) => c.name === 'serverguard-hub')
    hubConnected.value = !!statusResp.data?.hub?.connected
    const servers = serversResp.data.servers || []
    serverCount.value = servers.length
  } catch {
    // ignore
  }
}

// ─── sgctl 命令参考 ───
const sgctlCommands = [
  { cmd: 'sgctl status', desc: '查看 Agent 当前状态（运行模式、资源、健康评分）' },
  { cmd: 'sgctl doctor', desc: '系统诊断：检查 Agent 健康、配置、端口、磁盘等' },
  { cmd: 'sgctl top', desc: '查看受守护进程列表（类似 top 但只看受控进程）' },
  { cmd: 'sgctl guard list', desc: '列出所有受守护的服务进程' },
  { cmd: 'sgctl cert list', desc: '列出所有 SSL 证书及到期时间' },
  { cmd: 'sgctl finding list', desc: '查看安全扫描发现项' },
  { cmd: 'sgctl finding confirm <id>', desc: '确认安全发现项' },
  { cmd: 'sgctl finding false-positive <id>', desc: '标记安全发现项为误报' },
  { cmd: 'sgctl emergency-stop', desc: '紧急停止所有自动修复（只监控不操作）' },
  { cmd: 'sgctl emergency-resume', desc: '恢复自动修复' },
  { cmd: 'sgctl safety status', desc: '查看安全控制状态（熔断器、限额等）' },
  { cmd: 'sgctl config-version list', desc: '查看配置版本历史' },
  { cmd: 'sgctl config-version rollback <id>', desc: '回滚到指定配置版本' },
  { cmd: 'sgctl config-version export', desc: '导出当前配置为 YAML' },
  { cmd: 'sgctl config-version import <file>', desc: '从 YAML 导入配置' },
  { cmd: 'sgctl import baota/supervisor/...', desc: '从其他运维工具迁移配置' },
  { cmd: 'sgctl export metrics/alerts/audit', desc: '导出指标、告警、审计数据' },
  { cmd: 'sgctl db vacuum', desc: '压缩数据库（VACUUM）' },
  { cmd: 'sgctl db cleanup --days 30', desc: '按保留策略清理旧数据' },
  { cmd: 'sgctl security-check', desc: '检查 ServerGuard 自身安全漏洞' },
  { cmd: 'sgctl -s http://IP:8443 status', desc: '连接到远程 Hub/Agent 查询状态' },
  { cmd: 'sgctl -j status', desc: 'JSON 格式输出（方便脚本处理）' },
]

async function fetchComponents() {
  componentsLoading.value = true
  try {
    const resp = await axios.get('/api/version')
    components.value = resp.data.components || []
  } catch {
    components.value = []
  } finally {
    componentsLoading.value = false
  }
}

// ─── 每日巡检报告 ───
const reportLoading = ref(false)
const reportSending = ref(false)
const reportDialogVisible = ref(false)
const reportContent = ref('')

// ─── AI 增强 ───
const llmLoading = ref(false)
const llmSaving = ref(false)
const llmTesting = ref(false)
const llmTestResult = ref<{ type: string; text: string } | null>(null)
const llmStatus = ref<any>(null)
const llmConfig = reactive({
  provider: '',
  apiKey: '',
  apiBase: '',
  model: '',
  humanizeAlert: true,
  weeklyReport: true,
  explainIncident: true,
})

async function fetchLLMStatus() {
  llmLoading.value = true
  try {
    const resp = await axios.get('/api/llm/status')
    llmStatus.value = resp.data
    if (resp.data.config) {
      Object.assign(llmConfig, resp.data.config)
    }
  } catch {
    llmStatus.value = { enabled: false }
  } finally {
    llmLoading.value = false
  }
}

async function saveLLM() {
  llmSaving.value = true
  try {
    await axios.post('/api/llm/config', llmConfig)
    ElMessage.success('AI 配置已保存')
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.error || '保存失败')
  } finally {
    llmSaving.value = false
  }
}

async function testLLM() {
  llmTesting.value = true
  llmTestResult.value = null
  try {
    const resp = await axios.post('/api/llm/test')
    llmTestResult.value = { type: 'success', text: resp.data.message || '测试成功' }
  } catch (err: any) {
    llmTestResult.value = { type: 'error', text: err?.response?.data?.error || '测试失败' }
  } finally {
    llmTesting.value = false
  }
}

// ─── 双向通知 ───
const biNotifyLoading = ref(false)
const biNotify = reactive({ enabled: true })
const safetyStatus = ref<any>(null)
const remoteLoading = ref(false)
const pendingAlerts = ref<any[]>([])
const pendingLoading = ref(false)
const pendingPage = ref(1)
const pendingSize = ref(10)

async function fetchSafetyStatus() {
  biNotifyLoading.value = true
  try {
    const resp = await axios.get('/api/safety/status')
    safetyStatus.value = resp.data
    biNotify.enabled = resp.data.bidirectionalEnabled ?? true
  } catch {
    safetyStatus.value = null
  } finally {
    biNotifyLoading.value = false
  }
}

async function fetchPendingAlerts() {
  pendingLoading.value = true
  try {
    const resp = await axios.get('/api/notify/pending')
    pendingAlerts.value = resp.data.alerts || []
  } catch {
    pendingAlerts.value = []
  } finally {
    pendingLoading.value = false
  }
}

async function remotePause() {
  remoteLoading.value = true
  try {
    await axios.post('/api/safety/remote-pause')
    if (safetyStatus.value) safetyStatus.value.remotePaused = true
    ElMessage.success('已暂停自动修复')
  } catch {
    ElMessage.error('操作失败')
  } finally {
    remoteLoading.value = false
  }
}

async function remoteResume() {
  remoteLoading.value = true
  try {
    await axios.post('/api/safety/remote-resume')
    if (safetyStatus.value) safetyStatus.value.remotePaused = false
    ElMessage.success('已恢复自动修复')
  } catch {
    ElMessage.error('操作失败')
  } finally {
    remoteLoading.value = false
  }
}

async function pauseFor(row: any) {
  row._loading = true
  try {
    await axios.post(`/api/notify/pause/${row.shortCode}`)
    ElMessage.success(`已暂停 ${row.shortCode} 的自动修复`)
  } catch {
    ElMessage.error('操作失败')
  } finally {
    row._loading = false
  }
}

async function ackFor(row: any) {
  row._loading = true
  try {
    await axios.post(`/api/notify/ack/${row.shortCode}`)
    ElMessage.success(`已确认 ${row.shortCode}`)
    pendingAlerts.value = pendingAlerts.value.filter(a => a.shortCode !== row.shortCode)
  } catch {
    ElMessage.error('操作失败')
  } finally {
    row._loading = false
  }
}

function formatTime(ts: string): string {
  if (!ts) return '—'
  return dayjs(ts).format('MM-DD HH:mm')
}

function levelText(level: string): string {
  const labels: Record<string, string> = {
    critical: '严重', fatal: '致命', error: '错误', warning: '警告', info: '提醒',
  }
  return labels[level] || level || '—'
}

async function previewReport() {
  reportLoading.value = true
  try {
    const resp = await axios.get('/api/report/daily')
    reportContent.value = resp.data.report
    reportDialogVisible.value = true
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '获取报告失败')
  } finally {
    reportLoading.value = false
  }
}

async function sendReportNow() {
  reportSending.value = true
  try {
    await axios.post('/api/report/daily/send')
    ElMessage.success('巡检报告已推送到所有已启用渠道')
  } catch (err: any) {
    ElMessage.error(err.response?.data?.error || '发送失败')
  } finally {
    reportSending.value = false
  }
}

const settings = reactive({
  collect_interval: 5,
  learn_mode: true,
  max_memory_mb: 80,
  auto_renew_days: 14,
  kill_budget_hourly: 5,
  kill_budget_daily: 20,
  username: 'admin',
})

const notify = reactive({
wxpusher_app_token: '',
wxpusher_uid: '',
smtp_host: '',
smtp_port: '587',
smtp_user: '',
smtp_password: '',
email_to: '',
digest_enabled: false,
digest_hour: 8,
silence_enabled: false,
})

async function fetchSettings() {
  loading.value = true
  try {
    const resp = await axios.get('/api/settings')
    const data = resp.data
    Object.assign(settings, data)
    if (data.cert_ports) {
      certPortsStr.value = data.cert_ports.join(', ')
    }
  } catch (err) {
    ElMessage.error('加载设置失败')
  } finally {
    loading.value = false
  }
}

async function fetchNotifySettings() {
  notifyLoading.value = true
  try {
    const resp = await axios.get('/api/notify/settings')
    Object.assign(notify, resp.data)
  } catch (err) {
    ElMessage.error('加载通知设置失败')
  } finally {
    notifyLoading.value = false
  }
}

async function saveSettings() {
  saving.value = true
  try {
    await axios.post('/api/settings', settings)
    ElMessage.success('设置已保存')
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}

async function saveNotify() {
  notifySaving.value = true
  try {
    await axios.post('/api/notify/settings', notify)
    ElMessage.success('通知设置已保存并生效')
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    notifySaving.value = false
  }
}

async function testNotify() {
  testing.value = true
  try {
    const resp = await axios.post('/api/notify/test')
    ElMessage.success(resp.data.message || '测试通知已发送')
  } catch (err: any) {
    const msg = err?.response?.data?.error || '发送失败'
    ElMessage.error(msg)
  } finally {
    testing.value = false
  }
}

async function savePassword() {
  if (newPassword.value !== confirmPassword.value) {
    ElMessage.error('两次输入的密码不一致')
    return
  }
  if (newPassword.value && newPassword.value.length < 6) {
    ElMessage.warning('密码至少 6 位')
    return
  }
  saving.value = true
  try {
    await axios.post('/api/settings', {
      ...settings,
      new_password: newPassword.value,
    })
    ElMessage.success('密码已保存，下次登录生效')
    newPassword.value = ''
    confirmPassword.value = ''
  } catch (err) {
    ElMessage.error('保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  fetchSettings()
  fetchNotifySettings()
  fetchLLMStatus()
  fetchSafetyStatus()
  fetchPendingAlerts()
  fetchComponents()
  fetchHubStatus()
})
</script>

<style scoped>
.report-preview {
  margin: 0;
  padding: 16px;
  background: #f8fafd;
  border: 1px solid #e6eaf2;
  border-radius: 10px;
  font-size: 13px;
  line-height: 1.8;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 60vh;
  overflow-y: auto;
  font-family: inherit;
  color: #1e293b;
}
html.dark .report-preview {
  background: #1d2433;
  border-color: #33415584;
  color: #e2e8f0;
}

/* 多服务器部署步骤 */
.deploy-steps {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.deploy-step {
  display: flex;
  gap: 14px;
  align-items: flex-start;
}
.step-num {
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: #409eff;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  font-size: 14px;
}
.step-body {
  flex: 1;
  min-width: 0;
}
.step-title {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 4px;
  color: #1e293b;
}
html.dark .step-title {
  color: #e2e8f0;
}
.step-desc {
  font-size: 13px;
  color: #64748b;
  margin-bottom: 8px;
}
html.dark .step-desc {
  color: #94a3b8;
}

/* 命令块 */
.cmd-block {
  margin: 0;
  padding: 12px 16px;
  background: #1e293b;
  color: #e2e8f0;
  border-radius: 8px;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
html.dark .cmd-block {
  background: #0f172a;
  border: 1px solid #1d2433;
}

/* sgctl 命令参考 */
.cmd-text {
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
  font-size: 12.5px;
  color: #409eff;
}

/* 命令示例 */
.cmd-examples {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.cmd-example {
  border: 1px solid #e6eaf2;
  border-radius: 8px;
  overflow: hidden;
}
html.dark .cmd-example {
  border-color: #33415584;
}
.cmd-example-title {
  padding: 8px 14px;
  background: #f8fafd;
  font-size: 13px;
  font-weight: 600;
  color: #1e293b;
}
html.dark .cmd-example-title {
  background: #1d2433;
  color: #e2e8f0;
}
.cmd-example .cmd-block {
  border-radius: 0;
}
</style>
