﻿<template>
  <DefaultLayout>
    <!-- Hero Section -->
    <section class="hero">
      <div class="hero-bg">
        <div class="hero-glow"></div>
        <div class="hero-grid-pattern"></div>
      </div>
      <div class="container hero-content">
        <div class="hero-badge">
          <span class="pulse-dot"></span>
          v0.2.0 社区版现已发布 · 完全免费
        </div>
        <h1 class="hero-title">
          你的服务器<br />
          <span class="gradient-text">7×24 小时自动守护</span>
        </h1>
        <p class="hero-subtitle">
          资源监控 → 异常检测 → 自动修复 → 微信告警<br />
          16MB 单二进制，零依赖，装上就不用管。监控工具只负责告诉你"服务器死了"，<strong>ServerGuard 负责不让它死。</strong>
        </p>
        <div class="hero-actions">
          <div class="install-command">
            <span class="cmd-text">curl -sSL https://sg.jjtt.net/install.sh | bash</span>
            <button class="cmd-copy" @click="copyInstall">
              <el-icon><CopyDocument /></el-icon>
            </button>
          </div>
          <router-link to="/download" class="btn btn-outline btn-lg">
            <el-icon><Download /></el-icon>
            手动下载
          </router-link>
        </div>

        <div class="hero-features">
          <div class="hero-feature" v-for="f in heroFeatures" :key="f.text">
            <span class="check-icon">✓</span>
            {{ f.text }}
          </div>
        </div>
      </div>
    </section>

    <!-- Stats Bar -->
    <section class="stats-bar section-sm">
      <div class="container">
        <div class="stats-grid">
          <div class="stat-item" v-for="s in stats" :key="s.label">
            <div class="stat-value gradient-text">{{ s.value }}</div>
            <div class="stat-label">{{ s.label }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- Pain Points -->
    <section class="section">
      <div class="container">
        <div class="section-header">
          <h2>没有 ServerGuard 之前 vs 用了之后</h2>
          <p>每一个痛点，都是真实经历过的故障</p>
        </div>
        <div class="comparison-grid">
          <div class="comparison-item" v-for="c in comparisons" :key="c.before">
            <div class="comparison-before">
              <span class="emoji">😣</span>
              <p>{{ c.before }}</p>
            </div>
            <div class="comparison-arrow">→</div>
            <div class="comparison-after">
              <span class="emoji">😊</span>
              <p>{{ c.after }}</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Core Features -->
    <section class="section features-section">
      <div class="container">
        <div class="section-header">
          <h2>核心能力</h2>
          <p>不只是监控，是真的帮你解决问题</p>
        </div>
        <div class="features-grid">
          <div class="feature-card card" v-for="f in features" :key="f.title">
            <div class="feature-icon" :style="{ background: f.bg }">
              <span>{{ f.icon }}</span>
            </div>
            <h3>{{ f.title }}</h3>
            <p>{{ f.desc }}</p>
          </div>
        </div>
      </div>
    </section>

    <!-- Smart Features -->
    <section class="section smart-section">
      <div class="container">
        <div class="section-header">
          <h2>智能运维 · 越用越懂你的服务器</h2>
          <p>告警更少、更准、更有信息量。零外部依赖，不占资源</p>
        </div>
        <div class="smart-grid">
          <div class="smart-card card" v-for="s in smartFeatures" :key="s.title">
            <div class="smart-header">
              <span class="smart-icon">{{ s.icon }}</span>
              <h3>{{ s.title }}</h3>
            </div>
            <p>{{ s.desc }}</p>
            <div class="smart-detail" v-if="s.example">
              <pre>{{ s.example }}</pre>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Pricing Summary -->
    <section class="section pricing-preview">
      <div class="container">
        <div class="section-header">
          <h2>简单透明的定价</h2>
          <p>社区版永久免费 · 专业版 ¥299/年 · 无隐藏费用</p>
        </div>
        <div class="pricing-cards">
          <div class="pricing-card card" v-for="p in pricingSummary" :key="p.name"
            :class="{ popular: p.popular }">
            <div v-if="p.popular" class="popular-tag">最受欢迎</div>
            <h3 class="pricing-name">{{ p.name }}</h3>
            <p v-if="p.tagline" class="pricing-tagline">{{ p.tagline }}</p>
            <div class="pricing-price">
              <span class="price">{{ p.price }}</span>
              <span class="period">{{ p.period }}</span>
            </div>
            <ul class="pricing-features">
              <li v-for="f in p.features" :key="f">{{ f }}</li>
            </ul>
            <router-link to="/pricing" class="btn"
              :class="p.popular ? 'btn-primary' : 'btn-outline'">
              {{ p.cta }}
            </router-link>
          </div>
        </div>
      </div>
    </section>

    <!-- Testimonial -->
    <section class="section testimonial-section">
      <div class="container">
        <div class="testimonial-card">
          <p class="testimonial-quote">
            "装了一周帮我处理了 4 次问题，我一次都没被叫醒。磁盘满了自动清、
            SSL 快到期自动续、有人爆破 SSH 自动封。以前天天盯着服务器，
            现在服务器自己照顾自己。"
          </p>
          <div class="testimonial-author">
            <div class="author-avatar">👨‍💻</div>
            <div>
              <div class="author-name">某独立开发者</div>
              <div class="author-role">5 台服务器的全栈开发者</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- FAQ -->
    <section class="section faq-section">
      <div class="container">
        <div class="section-header">
          <h2>常见问题</h2>
          <p>打消你的顾虑</p>
        </div>
        <div class="faq-list">
          <details class="faq-item" v-for="(faq, i) in faqs" :key="i" open>
            <summary>
              <span class="faq-q">{{ faq.q }}</span>
              <span class="faq-icon">+</span>
            </summary>
            <p class="faq-a">{{ faq.a }}</p>
          </details>
        </div>
      </div>
    </section>

    <!-- CTA -->
    <section class="cta-section">
      <div class="container">
        <div class="cta-card">
          <h2>现在开始，让你的服务器自己照顾自己</h2>
          <p>30 秒安装，立即开始守护</p>
          <div class="cta-actions">
            <router-link to="/download" class="btn btn-primary btn-lg">
              <el-icon><Download /></el-icon>
              免费下载
            </router-link>
            <router-link to="/docs" class="btn btn-outline btn-lg">
              查看文档
            </router-link>
          </div>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import DefaultLayout from '@/components/DefaultLayout.vue'

const heroFeatures = [
  { text: '自动重启崩溃的服务' },
  { text: '自动清理暴涨的日志' },
  { text: 'SSL 证书自动续期' },
  { text: 'SSH 暴力破解自动封禁' },
  { text: '网站安全扫描' },
  { text: '服务器安全扫描' },
]

const stats = ref([
  { value: '16MB', label: '单二进制大小' },
  { value: '<50MB', label: '内存占用' },
  { value: '<1%', label: 'CPU 占用' },
  { value: '26', label: '守护模块' },
])

const comparisons = [
  { before: '凌晨3点磁盘满了，MySQL崩溃，网站打不开', after: '磁盘95%时自动清理旧日志，你睡觉时问题已经解决' },
  { before: '某个进程内存泄漏吃光内存，内核OOM随机杀进程', after: '检测到内存不足，智能终止非关键进程，发微信通知你' },
  { before: 'SSL证书过期忘了续，用户浏览器报红叉', after: '提前14天自动续期，续完自动reload并验证生效' },
  { before: 'SSH被暴力破解，被人挂马挖矿', after: '检测到5次失败登录自动封禁IP，发现挖矿进程直接杀掉' },
  { before: '日志文件涨到50GB把磁盘撑爆', after: '自动轮转压缩日志，排除web服务活跃日志' },
  { before: '服务器被植入WebShell后门', after: '扫描PHP文件特征码+3000+ YARA规则，发现立即告警' },
]

const features = [
  { icon: '🔥', title: '自动自愈', desc: '不只是告警，是真的修复。清理磁盘、重启进程、封禁IP、续期证书、清除木马', bg: 'rgba(231, 76, 60, 0.12)' },
  { icon: '🧠', title: '智能运维', desc: '告警收敛不刷屏、基线异常检测、磁盘写满预测、根因分析，越用越懂你的服务器', bg: 'rgba(108, 92, 231, 0.12)' },
  { icon: '🛡️', title: '安全防护', desc: 'SSH暴破封禁、WebShell检测、挖矿进程清理、文件篡改检测、攻击关联分析', bg: 'rgba(0, 212, 170, 0.12)' },
  { icon: '📜', title: '日志守护', desc: '日志暴涨自动轮转压缩、异常日志告警、日志文件大小监控', bg: 'rgba(243, 156, 18, 0.12)' },
  { icon: '🔐', title: '证书守护', desc: 'SSL证书到期前30天分级告警、14天自动续期、多CA降级链、续期失败告警', bg: 'rgba(0, 184, 148, 0.12)' },
  { icon: '🌐', title: '网站安全', desc: '敏感文件扫描、挂马篡改检测、后台暴露检测、配置安全审计、坏链检测', bg: 'rgba(85, 239, 196, 0.12)' },
  { icon: '📊', title: '健康评分', desc: '一图看清服务器健不健康，综合资源、服务、安全、证书多维度评分', bg: 'rgba(253, 203, 110, 0.12)' },
  { icon: '🔔', title: '全渠道告警', desc: '微信、邮件、钉钉、飞书、企业微信、Slack、Discord、Telegram，一个都不漏', bg: 'rgba(223, 230, 233, 0.12)' },
]

const smartFeatures = [
  {
    icon: '🔇', title: '告警收敛 — 不刷屏',
    desc: '同一条告警 10 分钟内重复触发 3 次，自动静默 10 分钟。同一个 IP 15 分钟内触发多种攻击告警，合并成一条事件摘要',
  },
  {
    icon: '📈', title: '基线异常检测 — 知道什么算"不正常"',
    desc: '按周几×小时把历史指标分成 168 个时段，分别学习正常范围（均值±3σ），偏离自身常态才告警',
    example: '> 基线异常：CPU 偏离历史正常范围\n> 当前值 87.2%，该时段（周二14时）近14天历史均值 42.1%（σ=8.3）',
  },
  {
    icon: '🔮', title: '磁盘写满预测 — 提前一周知道',
    desc: '对近 14 天的磁盘日均使用率做线性回归，算出每天涨多少、按这个速度哪天到 90%',
    example: '⚠️ /www 当前 78%，增速 2.1%/天\n预计 5 天后（08-16）达到 90%',
  },
  {
    icon: '🧩', title: '根因分析 — 告警里带着"为什么"',
    desc: '每次自动修复执行时，同步拍下系统快照（内存/Swap/磁盘/TOP进程），用启发式规则推测最可能的原因',
    example: '🧠 根因分析（自动推测）\n1. 内存压力极高(97%)，MySQL 很可能被 OOM Killer 终止\n2. Swap 使用率 82%，建议扩容内存',
  },
]

const pricingSummary = [
  {
    name: '社区版', price: '免费', period: '永久', tagline: '个人开发者首选', popular: false,
    features: ['资源守护', '进程保活', 'SSH 暴破拦截', '证书到期告警', '邮件+微信告警', '社区支持'],
    cta: '免费下载',
  },
  {
    name: '专业版', price: '¥299', period: '/年', tagline: '独立开发者/小团队', popular: true,
    features: ['社区版全部功能', '证书自动续期', '入侵检测', '网站安全扫描', '攻击预警+自动封禁', '全渠道告警'],
    cta: '立即购买',
  },
  {
    name: '企业版', price: '¥1,399', period: '/年', tagline: '中小企业/团队', popular: false,
    features: ['专业版全部功能', '多机 Hub 管控（20节点）', 'REST API 接口', 'RBAC 权限管理', '历史数据保留 1 年', '优先支持'],
    cta: '联系我们',
  },
]

const faqs = [
  { q: '支持哪些操作系统？', a: 'Windows Server 2016+ 和主流 Linux 发行版（Ubuntu 18.04+、CentOS 7+、Debian 10+、Rocky Linux 8+）。单二进制，无需安装运行时。' },
  { q: '会占用多少资源？', a: 'Agent 常驻内存 < 50MB，CPU < 1%。采用 Go 语言编写，单二进制 16MB，零外部依赖。不会像宝塔那样安装后增加 500MB+。' },
  { q: '和宝塔面板有什么区别？', a: '宝塔是 Web 管理面板（管网站/数据库），ServerGuard 是服务器守护系统（管服务器健康/安全/自愈）。两者互补，不冲突。ServerGuard 甚至能调用宝塔 API 自动续期 SSL 证书。' },
  { q: '会不会把我服务器搞崩？', a: '永远不会。五层安全机制：白名单进程永不杀、重启前配置预检、动作冲突智能排序、紧急停止按钮、所有操作可回滚。"该出手时不犹豫，不该碰的不碰。"' },
  { q: '社区版和专业版有什么区别？', a: '社区版功能足够个人开发者使用（资源监控+进程保活+日志防护+证书告警）。专业版增加了证书自动续期、入侵检测、文件篡改检测、全渠道告警等高级功能。社区版永久免费。' },
  { q: '可以离线使用吗？', a: '社区版完全离线可用。专业版支持在线/离线激活，离线 7 天宽限期。企业版支持完全离线部署。' },
  { q: '数据安全吗？会不会上传我的数据？', a: '不会。ServerGuard 采集的仅是系统指标（CPU/内存/磁盘/进程列表），不采集业务数据、数据库内容、用户密码、网站源码。所有数据存储在本地，告警通过你配置的渠道直接推送给你。' },
]

const copyInstall = async () => {
  try {
    await navigator.clipboard.writeText('curl -sSL https://sg.jjtt.net/install.sh | bash')
    ElMessage.success('安装命令已复制')
  } catch {
    ElMessage.warning('请手动复制安装命令')
  }
}
</script>

<style scoped>
/* Hero */
.hero {
  position: relative;
  padding: 80px 0 60px;
  overflow: hidden;
}
.hero-bg {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background: var(--gradient-hero);
  z-index: -1;
}
.hero-glow {
  position: absolute;
  top: -200px; left: 50%;
  transform: translateX(-50%);
  width: 800px; height: 600px;
  background: var(--gradient-glow);
}
.hero-grid-pattern {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background-image: 
    linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
  background-size: 40px 40px;
}
.hero-content {
  position: relative;
  text-align: center;
  max-width: 800px;
}
.hero-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: rgba(0, 212, 170, 0.1);
  border: 1px solid rgba(0, 212, 170, 0.2);
  border-radius: 20px;
  padding: 6px 16px;
  font-size: 13px;
  color: var(--sg-primary);
  margin-bottom: 24px;
}
.pulse-dot {
  width: 8px; height: 8px;
  background: var(--sg-primary);
  border-radius: 50%;
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
.hero-title {
  font-size: 56px;
  font-weight: 800;
  line-height: 1.15;
  margin-bottom: 20px;
}
.hero-subtitle {
  font-size: 18px;
  color: var(--text-secondary);
  margin-bottom: 36px;
  line-height: 1.7;
}
.hero-actions {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  margin-bottom: 40px;
  flex-wrap: wrap;
}
.install-command {
  display: flex;
  align-items: center;
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.cmd-text {
  padding: 14px 20px;
  font-family: 'Cascadia Code', 'Fira Code', monospace;
  font-size: 14px;
  color: var(--sg-primary);
}
.cmd-copy {
  background: rgba(0, 212, 170, 0.1);
  border: none;
  border-left: 1px solid var(--border-color);
  padding: 14px 16px;
  color: var(--sg-primary);
  cursor: pointer;
  transition: background 0.2s;
}
.cmd-copy:hover { background: rgba(0, 212, 170, 0.2); }
.hero-features {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 16px 24px;
}
.hero-feature {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 14px;
}
.check-icon {
  color: var(--sg-primary);
  font-weight: bold;
}

@media (max-width: 768px) {
  .hero-title { font-size: 36px; }
  .hero-subtitle { font-size: 16px; }
  .install-command { width: 100%; }
  .cmd-text { font-size: 12px; padding: 12px 16px; }
}

/* Stats */
.stats-bar {
  border-top: 1px solid var(--border-color);
  border-bottom: 1px solid var(--border-color);
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px;
}
.stat-item { text-align: center; }
.stat-value { font-size: 36px; font-weight: 800; }
.stat-label { color: var(--text-secondary); font-size: 14px; margin-top: 4px; }

/* Section Header */
.section-header {
  text-align: center;
  margin-bottom: 48px;
}
.section-header h2 {
  font-size: 32px;
  margin-bottom: 12px;
}
.section-header p {
  color: var(--text-secondary);
  font-size: 16px;
}

/* Comparison */
.comparison-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 20px;
}
.comparison-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 20px;
}
.comparison-before, .comparison-after {
  flex: 1;
}
.comparison-before p {
  color: var(--text-muted);
  font-size: 14px;
}
.comparison-after p {
  color: var(--text-primary);
  font-size: 14px;
}
.comparison-arrow {
  color: var(--sg-primary);
  font-size: 20px;
  font-weight: bold;
}
.emoji { font-size: 24px; }

/* Features */
.features-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
}
.feature-card {
  padding: 28px 24px;
}
.feature-icon {
  width: 48px; height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  margin-bottom: 16px;
}
.feature-card h3 { font-size: 17px; margin-bottom: 8px; }
.feature-card p { color: var(--text-secondary); font-size: 14px; line-height: 1.6; }

/* Smart */
.smart-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 24px;
}
.smart-card { padding: 28px; }
.smart-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.smart-icon { font-size: 28px; }
.smart-card h3 { font-size: 18px; }
.smart-card p { color: var(--text-secondary); font-size: 14px; line-height: 1.6; }
.smart-detail {
  margin-top: 16px;
}
.smart-detail pre {
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  font-family: 'Cascadia Code', monospace;
  font-size: 13px;
  color: var(--sg-primary);
  white-space: pre-wrap;
}

/* Pricing Preview */
.pricing-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 24px;
  max-width: 900px;
  margin: 0 auto;
}
.pricing-card {
  padding: 32px 28px;
  text-align: center;
  position: relative;
}
.pricing-card.popular {
  border-color: var(--sg-primary);
  box-shadow: var(--shadow-glow);
}
.popular-tag {
  position: absolute;
  top: -12px; left: 50%;
  transform: translateX(-50%);
  background: var(--gradient-primary);
  color: #fff;
  font-size: 12px;
  font-weight: 600;
  padding: 4px 16px;
  border-radius: 20px;
}
.pricing-name { font-size: 18px; margin-bottom: 4px; }
.pricing-tagline { font-size: 13px; color: var(--text-muted); margin-bottom: 12px; }
.pricing-price { margin-bottom: 24px; }
.pricing-price .price { font-size: 36px; font-weight: 800; }
.pricing-price .period { font-size: 14px; color: var(--text-muted); margin-left: 4px; }
.pricing-features {
  list-style: none;
  text-align: left;
  margin-bottom: 24px;
  min-height: 140px;
}
.pricing-features li {
  padding: 6px 0;
  color: var(--text-secondary);
  font-size: 14px;
}
.pricing-features li::before {
  content: '✓';
  color: var(--sg-primary);
  margin-right: 8px;
}

/* Testimonial */
.testimonial-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 48px;
  text-align: center;
  max-width: 800px;
  margin: 0 auto;
}
.testimonial-quote {
  font-size: 20px;
  line-height: 1.7;
  color: var(--text-primary);
  margin-bottom: 24px;
  font-style: italic;
}
.testimonial-author {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}
.author-avatar {
  width: 48px; height: 48px;
  border-radius: 50%;
  background: rgba(0, 212, 170, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
}
.author-name { font-weight: 600; }
.author-role { color: var(--text-muted); font-size: 14px; }

/* FAQ */
.faq-list {
  max-width: 800px;
  margin: 0 auto;
}
.faq-item {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  margin-bottom: 12px;
  overflow: hidden;
}
.faq-item summary {
  padding: 18px 24px;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 15px;
  font-weight: 500;
  color: var(--text-primary);
  list-style: none;
}
.faq-item summary::-webkit-details-marker { display: none; }
.faq-icon {
  color: var(--sg-primary);
  font-size: 20px;
  transition: transform 0.2s;
}
.faq-item[open] .faq-icon { transform: rotate(45deg); }
.faq-a {
  padding: 0 24px 18px;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.7;
}

/* CTA */
.cta-section {
  padding: 80px 0;
}
.cta-card {
  background: var(--gradient-hero);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 60px;
  text-align: center;
}
.cta-card h2 {
  font-size: 28px;
  margin-bottom: 12px;
}
.cta-card p {
  color: var(--text-secondary);
  margin-bottom: 32px;
}
.cta-actions {
  display: flex;
  gap: 16px;
  justify-content: center;
  flex-wrap: wrap;
}

@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .comparison-grid { grid-template-columns: 1fr; }
  .features-grid { grid-template-columns: 1fr; }
  .smart-grid { grid-template-columns: 1fr; }
  .pricing-cards { grid-template-columns: 1fr; }
  .cta-card { padding: 32px; }
}
</style>
