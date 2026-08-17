<template>
  <DefaultLayout>
    <section class="page-hero">
      <div class="container">
        <h1>关于 ServerGuard</h1>
        <p>让没有专职运维的中小企业，也能拥有 7×24 小时的服务器"免疫系统"</p>
      </div>
    </section>

    <section class="section">
      <div class="container narrow">
        <h2>我们的故事</h2>
        <p>
          ServerGuard 诞生于真实痛点。作为一个管理多条产品线（EdgeLite、PyGBSentry、JTE 等）的独立开发者，
          我管理着多台服务器，在过去一年中经历了 CPU 爆缸（273%）、日志暴涨（18.62GB）、
          僵尸进程残留、暴力破解入侵、SSL 证书过期等全部典型故障场景。
        </p>
        <p>
          每次故障都是凌晨被叫醒，SSH 登录排查，手动修复。我问自己：为什么没有一个工具，
          能在问题发生<strong>之前</strong>就预防，在问题发生<strong>之时</strong>就修复，
          而不是只发一条告警然后眼睁睁看着服务器崩掉？
        </p>
        <p>
          于是我写了 ServerGuard。它不是又一个监控工具，而是服务器的"免疫系统"——
          7×24 小时盯着你的服务器，发现问题直接动手修复，而不是只发告警。
        </p>

        <h2>我们的理念</h2>
        <div class="principles">
          <div class="principle card">
            <div class="principle-icon">🛡️</div>
            <h3>该出手时不犹豫</h3>
            <p>检测到磁盘快满了就自动清理，检测到进程死了就自动重启，检测到攻击就自动封禁。不做只说不做的花瓶。</p>
          </div>
          <div class="principle card">
            <div class="principle-icon">🚫</div>
            <h3>不该碰的不碰</h3>
            <p>白名单进程永不杀，重启前先做配置预检，所有操作可回滚。永远不会搞崩宝塔、IIS、Apache、MySQL、Nginx。</p>
          </div>
          <div class="principle card">
            <div class="principle-icon">🤝</div>
            <h3>不确定的交给你</h3>
            <p>安全扫描发现问题只建议+提示后果，不做自动修复。用户确认后才执行，最终判断权永远在你手里。</p>
          </div>
          <div class="principle card">
            <div class="principle-icon">🪶</div>
            <h3>轻量至上</h3>
            <p>16MB 单二进制，零依赖，内存 <50MB，CPU <1%。不会像宝塔那样安装后增加 500MB+。</p>
          </div>
        </div>

        <h2>Slogan</h2>
        <div class="slogan-box">
          <p class="slogan"><em>Install &amp; Forget. Guard &amp; Heal.</em></p>
          <p class="slogan-desc">装上就不用管，守护并且自愈。</p>
        </div>

        <h2>技术栈</h2>
        <div class="tech-grid">
          <div class="tech-item">Go 语言 — 单二进制跨平台</div>
          <div class="tech-item">Vue3 + Element Plus — Web 面板</div>
          <div class="tech-item">SQLite — 零依赖存储</div>
          <div class="tech-item">WebSocket — 实时通信</div>
          <div class="tech-item">systemd / Windows Service — 原生集成</div>
          <div class="tech-item">Ed25519 — 二进制签名</div>
        </div>

        <h2>开源协议</h2>
        <p>
          ServerGuard 社区版采用 <strong>AGPL-3.0</strong> 开源协议。社区版永久免费，
          功能足够个人开发者日常使用。专业版/企业版为商业授权（解除 AGPL 限制）。
        </p>
        <p>
          我们相信开源的力量。社区版不是"阉割版"，而是真正可用的产品。商业模式是
          "免费引流 → 专业版转化"，不是"先免费后收费"。
        </p>

        <h2>联系我们</h2>
        <div class="contact-links">
          <a href="mailto:support@serverguard.cn" class="contact-link card">
            <span>📧</span>
            <div>
              <strong>技术支持</strong>
              <p>support@serverguard.cn</p>
            </div>
          </a>
          <a href="mailto:security@serverguard.cn" class="contact-link card">
            <span>🔐</span>
            <div>
              <strong>安全披露</strong>
              <p>security@serverguard.cn</p>
            </div>
          </a>
          <a href="https://github.com/suoten/serverguard" target="_blank" class="contact-link card">
            <span>💻</span>
            <div>
              <strong>GitHub</strong>
              <p>github.com/suoten/serverguard</p>
            </div>
          </a>
        </div>
      </div>
    </section>
  </DefaultLayout>
</template>

<script setup lang="ts">
import DefaultLayout from '@/components/DefaultLayout.vue'
</script>

<style scoped>
.page-hero {
  padding: 60px 0 40px;
  text-align: center;
  background: var(--gradient-hero);
}
.page-hero h1 { font-size: 40px; margin-bottom: 12px; }
.page-hero p { color: var(--text-secondary); }

.narrow { max-width: 760px; }
.narrow h2 { font-size: 24px; margin: 40px 0 16px; }
.narrow p { color: var(--text-secondary); margin-bottom: 16px; line-height: 1.8; }

.principles { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
.principle { padding: 28px; }
.principle-icon { font-size: 32px; margin-bottom: 12px; }
.principle h3 { font-size: 17px; margin-bottom: 8px; }
.principle p { color: var(--text-secondary); font-size: 14px; margin: 0; }

.slogan-box {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 40px;
  text-align: center;
}
.slogan { font-size: 24px; font-style: italic; color: var(--sg-primary); }
.slogan-desc { color: var(--text-muted); font-size: 15px; margin-top: 8px; }

.tech-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
.tech-item {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 12px 16px;
  color: var(--text-secondary);
  font-size: 14px;
}

.contact-links { display: flex; flex-direction: column; gap: 12px; }
.contact-link {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px 24px;
  color: var(--text-primary);
}
.contact-link span { font-size: 28px; }
.contact-link strong { display: block; font-size: 15px; }
.contact-link p { color: var(--text-secondary); font-size: 14px; margin: 0; }

@media (max-width: 768px) {
  .principles { grid-template-columns: 1fr; }
  .tech-grid { grid-template-columns: 1fr; }
}
</style>
