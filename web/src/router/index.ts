import { createRouter, createWebHistory } from 'vue-router'
import Login from '@/views/Login.vue'
import AlertLanding from '@/views/AlertLanding.vue'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { public: true },
  },
  {
    path: '/alert/:id',
    name: 'AlertLanding',
    component: AlertLanding,
    meta: { public: true },
  },
  {
    path: '/',
    redirect: '/dashboard',
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: () => import('@/views/Dashboard.vue'),
  },
  {
    path: '/servers',
    name: 'Servers',
    component: () => import('@/views/Servers.vue'),
  },
  {
    path: '/alerts',
    name: 'Alerts',
    component: () => import('@/views/Alerts.vue'),
  },
  {
    path: '/guards',
    name: 'Guards',
    component: () => import('@/views/Guards.vue'),
  },
  {
    path: '/certs',
    name: 'Certs',
    component: () => import('@/views/Certs.vue'),
  },
  {
    path: '/logs',
    name: 'Logs',
    component: () => import('@/views/Logs.vue'),
  },
  {
    path: '/audit',
    name: 'Audit',
    component: () => import('@/views/Audit.vue'),
  },
  {
    path: '/monitoring',
    name: 'Monitoring',
    component: () => import('@/views/Monitoring.vue'),
  },
  {
    path: '/safety',
    name: 'Safety',
    component: () => import('@/views/Safety.vue'),
  },
  {
    path: '/baota',
    name: 'BaoTa',
    component: () => import('@/views/BaoTa.vue'),
  },
  {
    path: '/settings',
    name: 'Settings',
    component: () => import('@/views/Settings.vue'),
  },
  {
    path: '/findings',
    name: 'Findings',
    component: () => import('@/views/Findings.vue'),
  },
  {
    path: '/attacks',
    name: 'Attacks',
    component: () => import('@/views/Attacks.vue'),
  },
  {
    path: '/rbac',
    name: 'RBAC',
    component: () => import('@/views/RBAC.vue'),
  },
  {
    path: '/config-approval',
    name: 'ConfigApproval',
    component: () => import('@/views/ConfigApproval.vue'),
  },
  {
    path: '/rules',
    name: 'Rules',
    component: () => import('@/views/Rules.vue'),
  },
  {
    path: '/large-files',
    name: 'LargeFiles',
    component: () => import('@/views/LargeFiles.vue'),
  },
  {
    path: '/apm',
    name: 'Apm',
    component: () => import('@/views/Apm.vue'),
  },
  {
    path: '/knowledge',
    name: 'Knowledge',
    component: () => import('@/views/Knowledge.vue'),
  },
  {
    path: '/netquality',
    name: 'NetQuality',
    component: () => import('@/views/NetQuality.vue'),
  },
  {
    path: '/reports',
    name: 'Reports',
    component: () => import('@/views/Reports.vue'),
  },
  {
    path: '/maintenance-window',
    name: 'MaintenanceWindow',
    component: () => import('@/views/MaintenanceWindow.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Auth guard
router.beforeEach((to, _from, next) => {
  const token = localStorage.getItem('sg_token')
  if (to.meta.public || token) {
    next()
  } else {
    next('/login')
  }
})

export default router
