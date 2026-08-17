﻿<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>文档</h1>
        <p>从安装到精通，5 分钟上手 ServerGuard</p>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <div class="docs-grid">
          <div class="doc-card card" v-for="doc in docs" :key="doc.title">
            <div class="doc-icon">{{ doc.icon }}</div>
            <h3>{{ doc.title }}</h3>
            <p>{{ doc.desc }}</p>
            <div class="doc-links">
              <a v-for="link in doc.links" :key="link.name" :href="link.url" class="doc-link">
                {{ link.name }} →
              </a>
            </div>
          </div>
        </div>

        <!-- 快速开始 -->
        <div id="quickstart" class="doc-section card">
          <h2>⚡ 快速开始</h2>
          <p>5 分钟安装到运行：</p>
          <div class="qs-step">
            <div class="qs-num">1</div>
            <div>
              <strong>安装</strong>
              <div class="code-block">
                <span class="prompt">$</span>
                <span class="cmd">curl -sSL https://sg.jjtt.net/install.sh | bash</span>
              </div>
              <p class="step-desc">脚本自动识别 amd64/arm64，下载对应二进制并注册 systemd 服务。</p>
            </div>
          </div>
          <div class="qs-step">
            <div class="qs-num">2</div>
            <div>
              <strong>打开面板</strong>
              <p class="step-desc">浏览器访问 <code>http://127.0.0.1:18090</code>，默认账号 <code>admin / admin123</code>（首次登录请立即修改）。</p>
            </div>
          </div>
          <div class="qs-step">
            <div class="qs-num">3</div>
            <div>
              <strong>配置告警</strong>
              <p class="step-desc">面板 → 设置 → 告警通道，配置微信/邮件/钉钉/飞书等任一渠道。</p>
            </div>
          </div>
          <div class="qs-step">
            <div class="qs-num">4</div>
            <div>
              <strong>添加守护</strong>
              <p class="step-desc">面板 → 守护管理，添加需要保活的服务/进程/端口/网站。</p>
            </div>
          </div>
          <div class="qs-step">
            <div class="qs-num">5</div>
            <div>
              <strong>完成</strong>
              <p class="step-desc">ServerGuard 开始 7×24 小时守护。学习期（默认 7 天）内只告警不自动处置，之后自动放开自愈能力。</p>
            </div>
          </div>
        </div>

        <!-- 安装详解 -->
        <div id="install" class="doc-section card">
          <h2>📦 安装指南</h2>
          <h3>一键脚本（推荐）</h3>
          <div class="code-block">
            <span class="prompt">$</span>
            <span class="cmd">curl -sSL https://sg.jjtt.net/install.sh | bash</span>
          </div>
          <h3>手动安装</h3>
          <p>到<router-link to="/download">下载页</router-link>获取对应平台的二进制，然后：</p>
          <div class="code-block multi">
<span class="prompt">$</span> <span class="cmd">chmod +x serverguard-agent</span>
<span class="prompt">$</span> <span class="cmd">sudo mv serverguard-agent /usr/local/bin/</span>
<span class="prompt">$</span> <span class="cmd">sudo serverguard-agent -config /opt/serverguard/config.yaml</span>
          </div>
          <h3>卸载</h3>
          <div class="code-block multi">
<span class="prompt">$</span> <span class="cmd">sudo systemctl stop serverguard-agent</span>
<span class="prompt">$</span> <span class="cmd">sudo systemctl disable serverguard-agent</span>
<span class="prompt">$</span> <span class="cmd">sudo rm /usr/local/bin/serverguard-agent</span>
          </div>
        </div>

        <!-- 配置参考 -->
        <div id="config" class="doc-section card">
          <h2>⚙️ 配置文件</h2>
          <p>默认路径 <code>/opt/serverguard/config.yaml</code>，修改后 <code>systemctl restart serverguard-agent</code> 生效。核心配置：</p>
          <div class="code-block multi">
<span class="comment"># 数据与存储</span>
<span class="cmd">agent.data_dir: /opt/serverguard</span>
<span class="cmd">storage.max_size_mb: 200</span>          <span class="comment"># 本地指标库上限，超限自动清理</span>
<span class="comment"># 采集频率与资源上限</span>
<span class="cmd">agent.collect_interval: 10s</span>
<span class="cmd">agent.max_memory_mb: 50</span>           <span class="comment"># Agent 自身内存上限</span>
<span class="comment"># 学习模式（新装默认开启，只告警不自动处置）</span>
<span class="cmd">agent.learn_mode: true</span>
<span class="cmd">agent.learn_mode_days: 7</span>
<span class="comment"># 自动更新（对接官网）</span>
<span class="cmd">upgrade.server_url: https://sg.jjtt.net/api/v1</span>
<span class="cmd">upgrade.channel: stable</span>
<span class="cmd">upgrade.check_interval: 6h</span>
          </div>
        </div>

        <!-- 告警通道 -->
        <div id="alerts" class="doc-section card">
          <h2>🔔 告警通道</h2>
          <p>支持微信（Server酱/企业微信）、邮件、钉钉、飞书、Slack、Discord、Telegram。在面板 → 设置 → 告警通道 中填写 Webhook 或 SMTP 即可。</p>
          <ul class="plain-list">
            <li><strong>钉钉/飞书</strong>：群机器人 Webhook 地址粘贴即可，支持加签密钥</li>
            <li><strong>企业微信</strong>：群机器人 Webhook，图文消息直达</li>
            <li><strong>邮件</strong>：任意 SMTP（QQ/163/Gmail），支持 SSL/STARTTLS</li>
            <li><strong>电话告警</strong>：旗舰版可用，关键事件（如服务宕机）直接打电话</li>
          </ul>
          <p>告警收敛默认开启：同一告警 10 分钟内重复触发自动静默，避免刷屏。</p>
        </div>

        <!-- CLI -->
        <div id="cli" class="doc-section card">
          <h2>🛠️ sgctl 命令行工具</h2>
          <div class="code-block multi">
<span class="prompt">$</span> <span class="cmd">sgctl status</span>              <span class="comment"># 查看守护状态总览</span>
<span class="prompt">$</span> <span class="cmd">sgctl doctor</span>              <span class="comment"># 全面诊断（配置/权限/依赖/网络）</span>
<span class="prompt">$</span> <span class="cmd">sgctl logs --tail 50</span>     <span class="comment"># 查看最近日志</span>
<span class="prompt">$</span> <span class="cmd">sgctl restart &lt;name&gt;</span>     <span class="comment"># 重启指定守护模块</span>
<span class="prompt">$</span> <span class="cmd">sgctl upgrade</span>             <span class="comment"># 检查并执行升级</span>
<span class="prompt">$</span> <span class="cmd">sgctl activate &lt;key&gt;</span>     <span class="comment"># 激活专业版授权</span>
          </div>
        </div>

        <!-- 故障排查 -->
        <div id="troubleshoot" class="doc-section card">
          <h2>🔧 故障排查</h2>
          <h3>服务起不来</h3>
          <div class="code-block multi">
<span class="prompt">$</span> <span class="cmd">journalctl -u serverguard-agent -n 100 --no-pager</span>
<span class="prompt">$</span> <span class="cmd">sgctl doctor</span>   <span class="comment"># 一键定位配置/权限/端口问题</span>
          </div>
          <h3>面板打不开</h3>
          <ul class="plain-list">
            <li>面板默认仅监听 <code>127.0.0.1:18090</code>，远程访问需 SSH 隧道：<code>ssh -L 8080:127.0.0.1:18090 user@server</code></li>
            <li>确认进程在运行：<code>systemctl status serverguard-agent</code></li>
          </ul>
          <h3>收不到告警</h3>
          <ul class="plain-list">
            <li>面板 → 设置 → 告警通道 → 发送测试消息，验证通道连通性</li>
            <li>检查是否处于学习模式（学习期内部分自动处置被抑制，但告警正常发送）</li>
          </ul>
        </div>

        <!-- 反向代理 -->
        <div id="reverse-proxy" class="doc-section card">
          <h2>🌐 远程访问（反向代理）</h2>
          <p>Agent 面板默认监听 <code>127.0.0.1:18090</code>，仅本机可访问。远程访问推荐通过 Nginx 反向代理：</p>
          <div class="code-block multi">
<span class="comment"># /www/server/panel/vhost/nginx/serverguard.conf  （宝塔）</span>
<span class="comment"># 或 /etc/nginx/conf.d/serverguard.conf  （原生 Nginx）</span>
<span class="cmd">server {</span>
<span class="cmd">    listen 80;</span>
<span class="cmd">    server_name sg-agent.yourdomain.com;</span>
<span class="cmd">    location / {</span>
<span class="cmd">        proxy_pass http://127.0.0.1:18090;</span>
<span class="cmd">        proxy_set_header Host $host;</span>
<span class="cmd">        proxy_set_header X-Real-IP $remote_addr;</span>
<span class="cmd">        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;</span>
<span class="cmd">        proxy_set_header X-Forwarded-Proto $scheme;</span>
<span class="cmd">    }</span>
<span class="cmd">}</span>
          </div>
          <p>配置完成后 <code>nginx -t && nginx -s reload</code>，然后访问 <code>http://sg-agent.yourdomain.com</code>。</p>
          <p class="hint">建议配置 HTTPS（Let's Encrypt 免费证书），宝塔面板可一键申请。</p>
        </div>

        <!-- 从宝塔迁移 -->
        <div id="migrate" class="doc-section card">
          <h2>🔄 与宝塔共存 / 迁移</h2>
          <p>ServerGuard 与宝塔面板<strong>互补不冲突</strong>：宝塔管网站和数据库，ServerGuard 管服务器健康与安全。</p>
          <ul class="plain-list">
            <li>检测到宝塔环境时自动启用兼容模式，永不终止宝塔的 Python/MySQL/Nginx/PHP 进程</li>
            <li>可通过宝塔 API 联动：SSL 证书续期后直接同步到宝塔站点</li>
            <li>从 Monit/Supervisor 迁移：守护规则在面板一键导入，进程保活无缝接管</li>
          </ul>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import DefaultLayout from '@/components/DefaultLayout.vue'

const docs = [
  {
    icon: '🚀',
    title: '快速开始',
    desc: '5 分钟从安装到运行',
    links: [
      { name: '安装指南', url: '#install' },
      { name: '快速上手', url: '#quickstart' },
      { name: '配置文件', url: '#config' },
    ],
  },
  {
    icon: '⚙️',
    title: '配置参考',
    desc: '核心配置项说明',
    links: [
      { name: '配置文件', url: '#config' },
      { name: '告警通道', url: '#alerts' },
      { name: '自动更新', url: '#config' },
    ],
  },
  {
    icon: '🔔',
    title: '告警通知',
    desc: '8 种渠道任你选',
    links: [
      { name: '配置告警', url: '#alerts' },
      { name: '告警收敛', url: '#alerts' },
    ],
  },
  {
    icon: '🛠️',
    title: 'sgctl CLI',
    desc: '命令行管理工具',
    links: [
      { name: '常用命令', url: '#cli' },
      { name: '诊断工具', url: '#cli' },
    ],
  },
  {
    icon: '🔧',
    title: '故障排查',
    desc: '常见问题 + 诊断',
    links: [
      { name: 'sgctl doctor', url: '#troubleshoot' },
      { name: '常见问题', url: '#troubleshoot' },
      { name: '日志排查', url: '#troubleshoot' },
    ],
  },
  {
    icon: '🔄',
    title: '迁移指南',
    desc: '与现有工具共存',
    links: [
      { name: '与宝塔共存', url: '#migrate' },
      { name: '从 Monit 迁移', url: '#migrate' },
      { name: '从 Supervisor 迁移', url: '#migrate' },
    ],
  },
]
</script>

<style scoped>
.page-hero {
  padding: 60px 0 40px;
  text-align: center;
  background: var(--gradient-hero);
}
.page-hero h1 { font-size: 40px; margin-bottom: 12px; }
.page-hero p { color: var(--text-secondary); }

.docs-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
  margin-bottom: 48px;
}
.doc-card { padding: 28px; }
.doc-icon { font-size: 32px; margin-bottom: 12px; }
.doc-card h3 { font-size: 18px; margin-bottom: 8px; }
.doc-card > p { color: var(--text-secondary); font-size: 14px; margin-bottom: 16px; }
.doc-links { display: flex; flex-direction: column; gap: 8px; }
.doc-link { color: var(--sg-primary); font-size: 14px; }

.doc-section {
  padding: 40px;
  margin-bottom: 24px;
  scroll-margin-top: 80px;
}
.doc-section h2 { font-size: 22px; margin-bottom: 20px; }
.doc-section h3 { font-size: 16px; margin: 20px 0 10px; }
.doc-section > p { color: var(--text-secondary); font-size: 14px; margin-bottom: 12px; line-height: 1.7; }
.doc-section code {
  background: rgba(0, 0, 0, 0.3);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 13px;
  color: var(--sg-primary);
}
.plain-list { padding-left: 20px; margin-bottom: 12px; }
.plain-list li {
  color: var(--text-secondary);
  font-size: 14px;
  padding: 4px 0;
  line-height: 1.7;
}

.qs-step { display: flex; gap: 16px; margin-bottom: 20px; }
.qs-num {
  width: 32px; height: 32px;
  background: var(--gradient-primary);
  color: #fff;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  flex-shrink: 0;
}
.qs-step strong { font-size: 16px; }
.step-desc { color: var(--text-secondary); font-size: 14px; margin-top: 4px; line-height: 1.7; }
.code-block {
  display: flex;
  align-items: center;
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  gap: 8px;
  margin-top: 8px;
}
.code-block.multi {
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.8;
  overflow-x: auto;
}
.prompt { color: var(--text-muted); }
.cmd { color: var(--sg-primary); }
.comment { color: var(--text-muted); }

@media (max-width: 768px) {
  .docs-grid { grid-template-columns: 1fr; }
  .doc-section { padding: 24px; }
}
</style>
