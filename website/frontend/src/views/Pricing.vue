<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>简单透明的定价</h1>
        <p>社区版永久免费 · 专业版 ¥299/年 · 无隐藏费用 · 7天无理由退款</p>
        <div class="region-toggle">
          <button :class="!isOverseas ? 'active' : ''" @click="isOverseas = false">
            🇨🇳 中国（人民币）
          </button>
          <button :class="isOverseas ? 'active' : ''" @click="isOverseas = true">
            🌏 海外（USD）
          </button>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <!-- Pricing Cards -->
        <div class="plans-grid">
          <div class="plan-card card" v-for="p in plans" :key="p.name"
            :class="{ popular: p.popular, free: p.free }">
            <div v-if="p.popular" class="popular-tag">最受欢迎</div>
            <div v-if="p.free" class="free-tag">永久免费</div>
            <div class="plan-header">
              <h3>{{ p.name }}</h3>
              <p class="plan-tagline">{{ p.tagline }}</p>
            </div>
            <div class="plan-price">
              <span class="price-amount">{{ isOverseas ? p.priceUSD : p.priceCNY }}</span>
              <span class="price-period">{{ p.period }}</span>
            </div>
            <p v-if="p.note" class="plan-note">{{ p.note }}</p>
            <router-link to="/download" class="btn btn-lg w-full"
              :class="p.popular ? 'btn-primary' : 'btn-outline'">
              {{ p.cta }}
            </router-link>
            <ul class="plan-features">
              <li v-for="f in p.features" :key="f.text">
                <span class="feat-icon" :class="f.included ? 'yes' : 'no'">
                  {{ f.included ? '✓' : '—' }}
                </span>
                {{ f.text }}
              </li>
            </ul>
          </div>
        </div>

        <!-- Feature Comparison Table -->
        <div class="comparison-table-wrapper">
          <h2 class="table-title">详细功能对比</h2>
          <div class="table-scroll">
            <table class="comparison-table">
              <thead>
                <tr>
                  <th>功能</th>
                  <th>社区版</th>
                  <th class="highlight">专业版</th>
                  <th>企业版</th>
                  <th>旗舰版</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in comparisonRows" :key="row.feature">
                  <td class="feat-name">{{ row.feature }}</td>
                  <td v-for="(val, idx) in row.values" :key="idx"
                    :class="{ highlight: idx === 1 }">
                    <span v-if="val === true" class="check">✓</span>
                    <span v-else-if="val === false" class="cross">—</span>
                    <span v-else>{{ val }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Pricing FAQ -->
        <div class="pricing-faq">
          <h2 class="table-title">定价常见问题</h2>
          <div class="faq-list">
            <details class="faq-item" v-for="(faq, i) in pricingFAQs" :key="i" open>
              <summary>
                <span>{{ faq.q }}</span>
                <span class="faq-icon">+</span>
              </summary>
              <p class="faq-a">{{ faq.a }}</p>
            </details>
          </div>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import DefaultLayout from '@/components/DefaultLayout.vue'

const isOverseas = ref(false)

const plans = [
  {
    name: '社区版',
    tagline: '个人开发者首选',
    priceCNY: '¥0', priceUSD: '$0',
    period: '永久免费', free: true, popular: false,
    note: '开源（AGPL），功能足够日常使用',
    cta: '免费下载',
    features: [
      { text: '资源守护（CPU/内存/磁盘/网络）', included: true },
      { text: '进程保活', included: true },
      { text: '端口保活', included: true },
      { text: '日志防护', included: true },
      { text: 'SSH 暴破拦截', included: true },
      { text: '证书到期告警', included: true },
      { text: '邮件 + 微信告警', included: true },
      { text: '社区支持', included: true },
      { text: '证书自动续期', included: false },
      { text: '入侵检测', included: false },
    ],
  },
  {
    name: '专业版',
    tagline: '独立开发者/小团队',
    priceCNY: '¥299', priceUSD: '$49',
    period: '/年', free: false, popular: true,
    note: '3 台服务器，年付',
    cta: '立即购买',
    features: [
      { text: '社区版全部功能', included: true },
      { text: '证书自动续期（ACME + 宝塔 API）', included: true },
      { text: '入侵检测', included: true },
      { text: '文件篡改检测', included: true },
      { text: '数据库守护', included: true },
      { text: '网站安全扫描', included: true },
      { text: '漏洞扫描', included: true },
      { text: '攻击预警 + 自动封禁', included: true },
      { text: '全渠道告警（钉钉/飞书/企微/Slack/Telegram）', included: true },
      { text: '自动更新', included: true },
      { text: '多机 Hub 管控', included: false },
      { text: 'REST API 接口', included: false },
    ],
  },
  {
    name: '企业版',
    tagline: '中小企业/团队',
    priceCNY: '¥1,399', priceUSD: '$199',
    period: '/年', free: false, popular: false,
    note: '20 台服务器，含优先支持',
    cta: '购买企业版',
    features: [
      { text: '专业版全部功能', included: true },
      { text: '多机 Hub 集中管控（20 节点）', included: true },
      { text: '批量策略下发', included: true },
      { text: 'REST API 接口', included: true },
      { text: 'RBAC 权限管理', included: true },
      { text: '离线模式', included: true },
      { text: '操作审计（集中存储）', included: true },
      { text: '历史数据保留 1 年', included: true },
      { text: '优先技术支持', included: true },
    ],
  },
  {
    name: '旗舰版',
    tagline: '大型组织/高可用场景',
    priceCNY: '¥3,999', priceUSD: '$599',
    period: '/年', free: false, popular: false,
    note: '不限节点，含专属支持 + SLA 保障',
    cta: '联系销售',
    features: [
      { text: '企业版全部功能', included: true },
      { text: '不限节点数', included: true },
      { text: '电话告警', included: true },
      { text: '数据库主从切换', included: true },
      { text: '分布式选举与脑裂防护', included: true },
      { text: '跨云容灾探测', included: true },
      { text: '专属技术支持', included: true },
      { text: 'SLA 99.9% 保障', included: true },
      { text: '代运维托管（可选）', included: true },
    ],
  },
]

const comparisonRows = [
  { feature: '价格', values: ['免费', '¥299/年', '¥1,399/年', '¥3,999/年'] },
  { feature: '服务器数量', values: ['1 台', '3 台', '20 台', '不限'] },
  { feature: '资源守护', values: [true, true, true, true] },
  { feature: '进程保活', values: [true, true, true, true] },
  { feature: '日志防护', values: [true, true, true, true] },
  { feature: 'SSH 暴破拦截', values: [true, true, true, true] },
  { feature: '证书守护', values: ['仅告警', '自动续期', '自动续期', '自动续期'] },
  { feature: '入侵检测', values: [false, true, true, true] },
  { feature: '文件篡改检测', values: [false, true, true, true] },
  { feature: '数据库守护', values: [false, true, true, true] },
  { feature: '网站安全扫描', values: [false, true, true, true] },
  { feature: '漏洞扫描', values: [false, true, true, true] },
  { feature: '攻击预警 + 自动封禁', values: [false, true, true, true] },
  { feature: '告警通道', values: ['邮件+微信', '全渠道', '全渠道', '全渠道+电话'] },
  { feature: '自动更新', values: [false, true, true, true] },
  { feature: '多机 Hub 管控', values: [false, false, '20 节点', '不限'] },
  { feature: '批量策略下发', values: [false, false, true, true] },
  { feature: 'REST API', values: [false, false, true, true] },
  { feature: 'RBAC 权限', values: [false, false, true, true] },
  { feature: '历史数据保留', values: ['7 天', '90 天', '1 年', '无限'] },
  { feature: '技术支持', values: ['社区', '邮件', '优先', '专属'] },
  { feature: 'SLA 保障', values: [false, false, false, '99.9%'] },
  { feature: '代运维托管', values: [false, false, false, '可选'] },
]

const pricingFAQs = [
  { q: '能退款吗？', a: '可以。7 天无理由退款（官网直售），无任何条件。' },
  { q: '专业版为什么是年付？', a: '¥299/年对标宝塔专业版 ¥699/年，价格优势明显。年付模式让我们持续迭代有持续收入，你也能持续享受新功能更新。' },
  { q: '换服务器了怎么办？', a: '专业版/企业版支持在线解绑机器码，解绑后可在新服务器上重新激活。旧服务器完全失联时可提交"机器迁移申请"，验证账户所有权后人工解绑。' },
  { q: '支持哪些支付方式？', a: '中国：支付宝、微信支付。海外：PayPal、Stripe（信用卡）。企业版支持对公转账。' },
  { q: '社区版会一直免费吗？', a: '是的，社区版永久免费。我们的商业模式是"免费引流 → 专业版转化"，不是"先免费后收费"。社区版功能足够个人开发者日常使用。' },
  { q: '可以离线使用吗？', a: '社区版完全离线可用。专业版支持在线/离线激活，离线 7 天宽限期。企业版支持完全离线部署。' },
  { q: '企业版可以开发票吗？', a: '可以。企业版支持开具电子发票（国内）和 Receipt（海外），请在购买后联系客服。' },
  { q: '社区版和专业版的主要区别？', a: '社区版包含核心监控、保活、SSH暴破拦截和基础告警，够个人 1 台服务器日常使用。专业版增加了证书自动续期、入侵检测、安全扫描、攻击预警、全渠道告警，适合有安全需求的用户。' },
]
</script>

<style scoped>
.page-hero {
  padding: 60px 0 40px;
  text-align: center;
  background: var(--gradient-hero);
}
.page-hero h1 { font-size: 40px; margin-bottom: 12px; }
.page-hero > .container > p { color: var(--text-secondary); font-size: 16px; }

.region-toggle {
  margin-top: 32px;
  display: inline-flex;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.region-toggle button {
  background: transparent;
  border: none;
  padding: 10px 24px;
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
}
.region-toggle button.active {
  background: var(--gradient-primary);
  color: #fff;
}

/* Plans */
.plans-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 20px;
  margin-bottom: 80px;
}
.plan-card {
  padding: 32px 24px;
  position: relative;
  display: flex;
  flex-direction: column;
}
.plan-card.popular {
  border-color: var(--sg-primary);
  box-shadow: var(--shadow-glow);
}
.popular-tag, .free-tag {
  position: absolute;
  top: -12px; left: 50%;
  transform: translateX(-50%);
  font-size: 12px;
  font-weight: 600;
  padding: 4px 16px;
  border-radius: 20px;
  white-space: nowrap;
}
.popular-tag { background: var(--gradient-primary); color: #fff; }
.free-tag { background: rgba(39, 174, 96, 0.2); color: var(--sg-success); }
.plan-header { text-align: center; margin-bottom: 20px; }
.plan-header h3 { font-size: 20px; }
.plan-tagline { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
.plan-price { text-align: center; margin-bottom: 8px; }
.price-amount { font-size: 40px; font-weight: 800; }
.price-period { font-size: 14px; color: var(--text-muted); display: block; margin-top: 4px; }
.plan-note {
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
  margin-bottom: 20px;
  min-height: 32px;
}
.w-full { width: 100%; }
.plan-features {
  list-style: none;
  margin-top: 24px;
  flex: 1;
}
.plan-features li {
  padding: 8px 0;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  color: var(--text-secondary);
}
.feat-icon {
  width: 20px; height: 20px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: bold;
  flex-shrink: 0;
}
.feat-icon.yes { background: rgba(0, 212, 170, 0.15); color: var(--sg-primary); }
.feat-icon.no { background: rgba(107, 122, 153, 0.1); color: var(--text-muted); }

/* Comparison Table */
.table-title {
  text-align: center;
  font-size: 28px;
  margin-bottom: 32px;
}
.table-scroll {
  overflow-x: auto;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-color);
}
.comparison-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg-card);
}
.comparison-table th, .comparison-table td {
  padding: 12px 16px;
  text-align: center;
  border-bottom: 1px solid var(--border-color);
  font-size: 14px;
}
.comparison-table th {
  background: rgba(0, 0, 0, 0.2);
  font-weight: 600;
}
.comparison-table th.highlight, .comparison-table td.highlight {
  background: rgba(0, 212, 170, 0.04);
}
.feat-name {
  text-align: left !important;
  font-weight: 500;
  color: var(--text-primary);
}
.check { color: var(--sg-primary); font-weight: bold; }
.cross { color: var(--text-muted); }

/* FAQ */
.pricing-faq { margin-top: 80px; }
.faq-list { max-width: 800px; margin: 0 auto; }
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
.faq-icon { color: var(--sg-primary); font-size: 20px; }
.faq-item[open] .faq-icon { transform: rotate(45deg); }
.faq-a {
  padding: 0 24px 18px;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.7;
}

@media (max-width: 1024px) { .plans-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 768px) {
  .plans-grid { grid-template-columns: 1fr; }
  .page-hero h1 { font-size: 28px; }
}
</style>
