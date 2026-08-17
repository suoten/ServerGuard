import axios, { type AxiosInstance } from 'axios'

const api: AxiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
})

// 请求拦截：附加 admin token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sg_admin_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截：统一错误处理
api.interceptors.response.use(
  (resp) => resp,
  (error) => {
    if (error.response?.status === 401 && !error.config.url?.includes('/admin/login')) {
      localStorage.removeItem('sg_admin_token')
      window.location.href = '/admin/login'
    }
    return Promise.reject(error)
  }
)

// ===== 公共 API =====
export const publicAPI = {
  getContent: () => api.get('/content'),
  getPricing: () => api.get('/pricing'),
  getBlogList: (page = 1, pageSize = 10) =>
    api.get('/blog', { params: { page, page_size: pageSize } }),
  getBlogPost: (slug: string) => api.get(`/blog/${slug}`),
  getSecurityList: (page = 1, pageSize = 20) =>
    api.get('/security', { params: { page, page_size: pageSize } }),
  getVersions: () => api.get('/versions'),
  getLatestVersion: (params: { channel?: string; os?: string; arch?: string }) =>
    api.get('/latest', { params }),
  getStats: () => api.get('/stats'),
}

// ===== Admin API =====
export const adminAPI = {
  login: (username: string, password: string) =>
    api.post('/admin/login', { username, password }),
  getContent: () => api.get('/admin/content'),
  updateContent: (data: Record<string, unknown>) =>
    api.put('/admin/content', data),
  getPricing: () => api.get('/admin/pricing'),
  updatePricing: (data: Record<string, unknown>) =>
    api.put('/admin/pricing', data),
  // Versions
  getVersions: () => api.get('/admin/versions'),
  createVersion: (data: FormData) =>
    api.post('/admin/versions', data, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  updateVersion: (id: number, data: Record<string, unknown>) =>
    api.put(`/admin/versions/${id}`, data),
  deleteVersion: (id: number) => api.delete(`/admin/versions/${id}`),
  // Blog
  getBlogList: (page = 1, pageSize = 20) =>
    api.get('/admin/blog', { params: { page, page_size: pageSize } }),
  createBlogPost: (data: Record<string, unknown>) =>
    api.post('/admin/blog', data),
  updateBlogPost: (id: number, data: Record<string, unknown>) =>
    api.put(`/admin/blog/${id}`, data),
  deleteBlogPost: (id: number) => api.delete(`/admin/blog/${id}`),
  // Security
  getSecurityList: (page = 1, pageSize = 20) =>
    api.get('/admin/security', { params: { page, page_size: pageSize } }),
  createSecurityAdvisory: (data: Record<string, unknown>) =>
    api.post('/admin/security', data),
  updateSecurityAdvisory: (id: number, data: Record<string, unknown>) =>
    api.put(`/admin/security/${id}`, data),
  deleteSecurityAdvisory: (id: number) =>
    api.delete(`/admin/security/${id}`),
  // Stats
  getDashboardStats: () => api.get('/admin/stats'),
  // Password
  changePassword: (oldPassword: string, newPassword: string) =>
    api.put('/admin/password', { old_password: oldPassword, new_password: newPassword }),
}

export default api
