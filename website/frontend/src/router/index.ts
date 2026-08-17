import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
// 静态导入所有组件，避免动态 import() 在某些浏览器中失败
import Home from '@/views/Home.vue'
import Pricing from '@/views/Pricing.vue'
import Download from '@/views/Download.vue'
import Blog from '@/views/Blog.vue'
import BlogPost from '@/views/BlogPost.vue'
import Security from '@/views/Security.vue'
import About from '@/views/About.vue'
import Docs from '@/views/Docs.vue'
import NotFound from '@/views/NotFound.vue'
import AdminLogin from '@/views/admin/AdminLogin.vue'
import AdminLayout from '@/views/admin/AdminLayout.vue'
import AdminDashboard from '@/views/admin/AdminDashboard.vue'
import AdminContent from '@/views/admin/AdminContent.vue'
import AdminPricing from '@/views/admin/AdminPricing.vue'
import AdminVersions from '@/views/admin/AdminVersions.vue'
import AdminBlog from '@/views/admin/AdminBlog.vue'
import AdminSecurity from '@/views/admin/AdminSecurity.vue'

const routes: RouteRecordRaw[] = [
  { path: '/', name: 'Home', component: Home, meta: { title: 'ServerGuard · 让服务器自己照顾自己' } },
  { path: '/pricing', name: 'Pricing', component: Pricing, meta: { title: '定价 · ServerGuard' } },
  { path: '/download', name: 'Download', component: Download, meta: { title: '下载 · ServerGuard' } },
  { path: '/blog', name: 'Blog', component: Blog, meta: { title: '博客 · ServerGuard' } },
  { path: '/blog/:slug', name: 'BlogPost', component: BlogPost, meta: { title: '博客 · ServerGuard' } },
  { path: '/security', name: 'Security', component: Security, meta: { title: '安全公告 · ServerGuard' } },
  { path: '/about', name: 'About', component: About, meta: { title: '关于我们 · ServerGuard' } },
  { path: '/docs', name: 'Docs', component: Docs, meta: { title: '文档 · ServerGuard' } },
  { path: '/admin/login', name: 'AdminLogin', component: AdminLogin, meta: { title: '管理后台登录 · ServerGuard', noLayout: true } },
  {
    path: '/admin', component: AdminLayout,
    children: [
      { path: '', name: 'AdminDashboard', component: AdminDashboard, meta: { title: '仪表盘 · 管理后台' } },
      { path: 'content', name: 'AdminContent', component: AdminContent, meta: { title: '网站内容 · 管理后台' } },
      { path: 'pricing', name: 'AdminPricing', component: AdminPricing, meta: { title: '定价管理 · 管理后台' } },
      { path: 'versions', name: 'AdminVersions', component: AdminVersions, meta: { title: '版本管理 · 管理后台' } },
      { path: 'blog', name: 'AdminBlog', component: AdminBlog, meta: { title: '博客管理 · 管理后台' } },
      { path: 'security', name: 'AdminSecurity', component: AdminSecurity, meta: { title: '安全公告管理 · 管理后台' } },
    ],
  },
  { path: '/:pathMatch(.*)*', name: 'NotFound', component: NotFound, meta: { title: '页面不存在 · ServerGuard' } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() { return { top: 0 } },
})

router.afterEach((to) => {
  document.title = (to.meta.title as string) || 'ServerGuard'
})

export default router
