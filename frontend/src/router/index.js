import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '../composables/auth'

const routes = [
  {
    path: '/login',
    component: () => import('../views/Login.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    children: [
      { path: '', redirect: '/tasks' },
      { path: 'tasks', name: 'tasks', component: () => import('../views/TaskPanel.vue'), meta: { title: '任务面板' } },
      { path: 'collect/:taskId?', name: 'collect', component: () => import('../views/Collect.vue'), meta: { title: '接口采集' } },
      // AI 研判已并入接口采集 Tab；旧链接重定向
      { path: 'review/:taskId?', redirect: (to) => ({ path: `/collect/${to.params.taskId || ''}`, query: { tab: 'review' } }) },
      { path: 'config', name: 'config', component: () => import('../views/ScanConfig.vue'), meta: { title: '扫描配置' } },
      { path: 'vulns/:taskId?', name: 'vulns', component: () => import('../views/VulnList.vue'), meta: { title: '漏洞结果' } },
      { path: 'kb', name: 'kb', component: () => import('../views/Knowledge.vue'), meta: { title: '知识库' } },
      { path: 'audit', name: 'audit', component: () => import('../views/AuditLog.vue'), meta: { title: '审计日志' } },
    ],
  },
]

export const router = createRouter({ history: createWebHistory(), routes })

// 路由守卫：未登录一律去 /login
router.beforeEach((to) => {
  const auth = useAuth()
  if (!to.meta.public && !auth.token) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
})
