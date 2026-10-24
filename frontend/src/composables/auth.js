import { reactive } from 'vue'

/**
 * 登录态共享（单例）：
 *  token 从 localStorage 恢复；logout() 清空并跳登录。
 */
export const authState = reactive({
  token: localStorage.getItem('mhszed_token') || '',
  username: localStorage.getItem('mhszed_username') || '',
  role: localStorage.getItem('mhszed_role') || '',
})

export function setLogin({ token, username, role }) {
  authState.token = token
  authState.username = username
  authState.role = role
  localStorage.setItem('mhszed_token', token)
  localStorage.setItem('mhszed_username', username)
  localStorage.setItem('mhszed_role', role)
}

export function logout() {
  authState.token = ''
  authState.username = ''
  authState.role = ''
  localStorage.removeItem('mhszed_token')
  localStorage.removeItem('mhszed_username')
  localStorage.removeItem('mhszed_role')
  location.href = '/login'
}

export function useAuth() {
  return authState
}
