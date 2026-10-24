import axios from 'axios'
import { ElMessage } from 'element-plus'

/**
 * 全局 axios 实例：
 *  - 自动携带 Bearer token（localStorage.mhszed_token）
 *  - 401 → 清 token 跳登录
 *  - 统一错误提示（不吞异常，业务侧按需再 catch）
 */
const http = axios.create({ baseURL: '/api', timeout: 30000 })

http.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('mhszed_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

http.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status
    const detail = err.response?.data?.detail
    if (status === 401) {
      localStorage.removeItem('mhszed_token')
      if (location.pathname !== '/login') location.href = '/login'
    } else {
      ElMessage.error(typeof detail === 'string' ? detail : `请求失败 (${status ?? '网络错误'})`)
    }
    return Promise.reject(err)
  },
)

export default http
